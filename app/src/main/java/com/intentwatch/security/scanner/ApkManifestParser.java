package com.intentwatch.security.scanner;

import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.net.Uri;
import android.util.Log;

import com.intentwatch.security.models.DiscoveredDeepLink;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

/**
 * Parses AndroidManifest.xml directly from an APK file without installation.
 * Implements Android Binary XML (AXML) decoding to extract declared activities,
 * intent-filters, schemes, hosts, paths, categories, and exported status.
 */
public class ApkManifestParser {
    private static final String TAG = "ApkManifestParser";

    // AXML Chunk Types
    private static final int CHUNK_AXML_HEADER = 0x00080003;
    private static final int CHUNK_STRING_POOL = 0x001C0001;
    private static final int CHUNK_RESOURCE_MAP = 0x00080180;
    private static final int CHUNK_START_NAMESPACE = 0x00100100;
    private static final int CHUNK_END_NAMESPACE = 0x00100101;
    private static final int CHUNK_START_TAG = 0x00100102;
    private static final int CHUNK_END_TAG = 0x00100103;
    private static final int CHUNK_TEXT = 0x00100104;

    public static class ParseResult {
        public String packageName = "";
        public String appName = "";
        public List<DiscoveredDeepLink> deepLinks = new ArrayList<>();
        public boolean success = false;
        public String errorMessage = "";
    }

    /**
     * Parses an APK provided via URI (Storage Access Framework).
     */
    public static ParseResult parseApkFromUri(Context context, Uri apkUri) {
        ParseResult result = new ParseResult();
        File tempApk = null;
        try {
            // Read APK bytes from content resolver
            InputStream is = context.getContentResolver().openInputStream(apkUri);
            if (is == null) {
                result.errorMessage = "Unable to open input stream from selected URI.";
                return result;
            }

            tempApk = File.createTempFile("inspect_", ".apk", context.getCacheDir());
            FileOutputStream fos = new FileOutputStream(tempApk);
            byte[] buf = new byte[16384];
            int len;
            while ((len = is.read(buf)) != -1) {
                fos.write(buf, 0, len);
            }
            fos.flush();
            fos.close();
            is.close();

            // Extract application info using Android PackageManager archive API
            PackageManager pm = context.getPackageManager();
            PackageInfo pi = pm.getPackageArchiveInfo(tempApk.getAbsolutePath(), PackageManager.GET_ACTIVITIES);
            if (pi != null) {
                result.packageName = pi.packageName;
                if (pi.applicationInfo != null) {
                    pi.applicationInfo.sourceDir = tempApk.getAbsolutePath();
                    pi.applicationInfo.publicSourceDir = tempApk.getAbsolutePath();
                    CharSequence label = pi.applicationInfo.loadLabel(pm);
                    result.appName = label != null ? label.toString() : pi.packageName;
                }
            }
            if (result.appName.isEmpty()) {
                result.appName = tempApk.getName();
            }

            // Extract and decode AndroidManifest.xml binary XML
            byte[] manifestBytes = extractManifestBytes(tempApk);
            if (manifestBytes != null) {
                List<DiscoveredDeepLink> extracted = decodeAxmlManifest(manifestBytes, result.appName, result.packageName);
                result.deepLinks.addAll(extracted);
                result.success = true;
            } else {
                result.errorMessage = "Could not locate AndroidManifest.xml inside the APK archive.";
            }

        } catch (Exception e) {
            Log.e(TAG, "Error inspecting APK: " + e.getMessage(), e);
            result.errorMessage = "Inspection failed: " + e.getMessage();
        } finally {
            if (tempApk != null && tempApk.exists()) {
                //noinspection ResultOfMethodCallIgnored
                tempApk.delete();
            }
        }
        return result;
    }

    private static byte[] extractManifestBytes(File apkFile) {
        try (ZipInputStream zis = new ZipInputStream(new java.io.FileInputStream(apkFile))) {
            ZipEntry entry;
            while ((entry = zis.getNextEntry()) != null) {
                if ("AndroidManifest.xml".equalsIgnoreCase(entry.getName())) {
                    ByteArrayOutputStream baos = new ByteArrayOutputStream();
                    byte[] buffer = new byte[8192];
                    int r;
                    while ((r = zis.read(buffer)) != -1) {
                        baos.write(buffer, 0, r);
                    }
                    return baos.toByteArray();
                }
            }
        } catch (Exception e) {
            Log.e(TAG, "Error reading ZIP stream: " + e.getMessage());
        }
        return null;
    }

    /**
     * Decodes the binary AndroidManifest.xml (AXML format) and extracts intent filters.
     */
    public static List<DiscoveredDeepLink> decodeAxmlManifest(byte[] data, String appName, String fallbackPkg) {
        List<DiscoveredDeepLink> list = new ArrayList<>();
        try {
            ByteBuffer buffer = ByteBuffer.wrap(data);
            buffer.order(ByteOrder.LITTLE_ENDIAN);

            int header = buffer.getInt();
            if (header != CHUNK_AXML_HEADER) {
                Log.w(TAG, "Invalid AXML magic header: " + Integer.toHexString(header));
                return list;
            }

            int fileSize = buffer.getInt();
            List<String> stringPool = new ArrayList<>();
            String currentPkg = fallbackPkg;

            String currentActivity = null;
            boolean currentActivityExported = false;
            String currentLaunchMode = "standard";

            boolean insideIntentFilter = false;
            boolean hasActionView = false;
            boolean isBrowsable = false;
            boolean isDefault = false;
            boolean autoVerify = false;

            List<DataTag> dataTags = new ArrayList<>();

            while (buffer.hasRemaining()) {
                int chunkType = buffer.getInt();
                int chunkSize = buffer.getInt();

                if (chunkType == CHUNK_STRING_POOL) {
                    stringPool = parseStringPool(buffer, chunkSize);
                } else if (chunkType == CHUNK_START_TAG) {
                    int lineNumber = buffer.getInt();
                    int commentIdx = buffer.getInt();
                    int nsIdx = buffer.getInt();
                    int nameIdx = buffer.getInt();
                    int attrStart = buffer.getShort();
                    int attrSize = buffer.getShort();
                    int attrCount = buffer.getShort();

                    String tagName = getString(stringPool, nameIdx);

                    if ("manifest".equalsIgnoreCase(tagName)) {
                        for (int i = 0; i < attrCount; i++) {
                            int aNs = buffer.getInt();
                            int aName = buffer.getInt();
                            int aRawVal = buffer.getInt();
                            int aType = buffer.getInt();
                            int aData = buffer.getInt();
                            String attrName = getString(stringPool, aName);
                            if ("package".equals(attrName)) {
                                currentPkg = getString(stringPool, aRawVal);
                            }
                        }
                    } else if ("activity".equalsIgnoreCase(tagName) || "activity-alias".equalsIgnoreCase(tagName)) {
                        currentActivity = "";
                        currentActivityExported = false;
                        currentLaunchMode = "standard";
                        insideIntentFilter = false;

                        for (int i = 0; i < attrCount; i++) {
                            int aNs = buffer.getInt();
                            int aName = buffer.getInt();
                            int aRawVal = buffer.getInt();
                            int aType = buffer.getInt();
                            int aData = buffer.getInt();
                            String attrName = getString(stringPool, aName);

                            if ("name".equals(attrName)) {
                                currentActivity = getString(stringPool, aRawVal);
                            } else if ("exported".equals(attrName)) {
                                currentActivityExported = (aData != 0);
                            } else if ("launchMode".equals(attrName)) {
                                currentLaunchMode = decodeLaunchMode(aData);
                            }
                        }
                    } else if ("intent-filter".equalsIgnoreCase(tagName)) {
                        insideIntentFilter = true;
                        hasActionView = false;
                        isBrowsable = false;
                        isDefault = false;
                        autoVerify = false;
                        dataTags.clear();

                        for (int i = 0; i < attrCount; i++) {
                            int aNs = buffer.getInt();
                            int aName = buffer.getInt();
                            int aRawVal = buffer.getInt();
                            int aType = buffer.getInt();
                            int aData = buffer.getInt();
                            String attrName = getString(stringPool, aName);
                            if ("autoVerify".equals(attrName)) {
                                autoVerify = (aData != 0);
                            }
                        }
                    } else if ("action".equalsIgnoreCase(tagName) && insideIntentFilter) {
                        for (int i = 0; i < attrCount; i++) {
                            int aNs = buffer.getInt();
                            int aName = buffer.getInt();
                            int aRawVal = buffer.getInt();
                            int aType = buffer.getInt();
                            int aData = buffer.getInt();
                            String val = getString(stringPool, aRawVal);
                            if ("android.intent.action.VIEW".equals(val)) {
                                hasActionView = true;
                            }
                        }
                    } else if ("category".equalsIgnoreCase(tagName) && insideIntentFilter) {
                        for (int i = 0; i < attrCount; i++) {
                            int aNs = buffer.getInt();
                            int aName = buffer.getInt();
                            int aRawVal = buffer.getInt();
                            int aType = buffer.getInt();
                            int aData = buffer.getInt();
                            String val = getString(stringPool, aRawVal);
                            if ("android.intent.category.BROWSABLE".equals(val)) {
                                isBrowsable = true;
                            } else if ("android.intent.category.DEFAULT".equals(val)) {
                                isDefault = true;
                            }
                        }
                    } else if ("data".equalsIgnoreCase(tagName) && insideIntentFilter) {
                        DataTag dt = new DataTag();
                        for (int i = 0; i < attrCount; i++) {
                            int aNs = buffer.getInt();
                            int aName = buffer.getInt();
                            int aRawVal = buffer.getInt();
                            int aType = buffer.getInt();
                            int aData = buffer.getInt();
                            String attrName = getString(stringPool, aName);
                            String rawVal = getString(stringPool, aRawVal);

                            if ("scheme".equals(attrName)) dt.scheme = rawVal;
                            else if ("host".equals(attrName)) dt.host = rawVal;
                            else if ("port".equals(attrName)) dt.port = rawVal;
                            else if ("path".equals(attrName)) dt.path = rawVal;
                            else if ("pathPrefix".equals(attrName)) dt.pathPrefix = rawVal;
                            else if ("pathPattern".equals(attrName)) dt.pathPattern = rawVal;
                        }
                        dataTags.add(dt);
                    } else {
                        // Skip unhandled tag attributes
                        buffer.position(buffer.position() + (attrCount * 20));
                    }

                } else if (chunkType == CHUNK_END_TAG) {
                    int lineNumber = buffer.getInt();
                    int commentIdx = buffer.getInt();
                    int nsIdx = buffer.getInt();
                    int nameIdx = buffer.getInt();
                    String tagName = getString(stringPool, nameIdx);

                    if ("intent-filter".equalsIgnoreCase(tagName) && insideIntentFilter) {
                        if (hasActionView || !dataTags.isEmpty()) {
                            for (DataTag dt : dataTags) {
                                if (dt.scheme != null && !dt.scheme.isEmpty()) {
                                    DiscoveredDeepLink item = new DiscoveredDeepLink();
                                    item.setAppName(appName);
                                    item.setPackageName(currentPkg);
                                    item.setActivityName(currentActivity != null ? currentActivity : "UnknownActivity");
                                    item.setScheme(dt.scheme);
                                    item.setHost(dt.host);
                                    item.setPort(dt.port);
                                    item.setPath(dt.path);
                                    item.setPathPrefix(dt.pathPrefix);
                                    item.setPathPattern(dt.pathPattern);
                                    item.setExported(currentActivityExported);
                                    item.setHasActionView(hasActionView);
                                    item.setBrowsable(isBrowsable);
                                    item.setDefaultCategory(isDefault);
                                    item.setAutoVerify(autoVerify);
                                    item.setLaunchMode(currentLaunchMode);
                                    item.setDiscoverySource("APK_FILE");
                                    item.setAnalysisStatus("PARSED_AXML");
                                    item.setRiskScore(calculateBaselineRisk(item));
                                    list.add(item);
                                }
                            }
                        }
                        insideIntentFilter = false;
                        dataTags.clear();
                    } else if ("activity".equalsIgnoreCase(tagName) || "activity-alias".equalsIgnoreCase(tagName)) {
                        currentActivity = null;
                    }
                } else {
                    // Skip unsupported chunks
                    int skip = chunkSize - 8;
                    if (skip > 0 && buffer.position() + skip <= buffer.limit()) {
                        buffer.position(buffer.position() + skip);
                    }
                }
            }
        } catch (Exception e) {
            Log.e(TAG, "Error decoding AXML: " + e.getMessage());
        }
        return list;
    }

    private static List<String> parseStringPool(ByteBuffer buffer, int chunkSize) {
        List<String> pool = new ArrayList<>();
        try {
            int stringCount = buffer.getInt();
            int styleCount = buffer.getInt();
            int flags = buffer.getInt();
            int stringsOffset = buffer.getInt();
            int stylesOffset = buffer.getInt();

            boolean isUtf8 = (flags & (1 << 8)) != 0;

            int[] offsets = new int[stringCount];
            for (int i = 0; i < stringCount; i++) {
                offsets[i] = buffer.getInt();
            }

            int stringPoolStart = buffer.position() - (stringCount * 4) - 20;

            for (int i = 0; i < stringCount; i++) {
                buffer.position(stringPoolStart + stringsOffset + offsets[i]);
                if (isUtf8) {
                    int len1 = buffer.get() & 0xFF;
                    int len2 = buffer.get() & 0xFF;
                    byte[] bytes = new byte[len2];
                    buffer.get(bytes);
                    pool.add(new String(bytes, "UTF-8"));
                } else {
                    int charCount = buffer.getShort() & 0xFFFF;
                    char[] chars = new char[charCount];
                    for (int j = 0; j < charCount; j++) {
                        chars[j] = buffer.getChar();
                    }
                    pool.add(new String(chars));
                }
            }
        } catch (Exception e) {
            Log.w(TAG, "Exception parsing string pool: " + e.getMessage());
        }
        return pool;
    }

    private static String getString(List<String> pool, int index) {
        if (index >= 0 && index < pool.size()) {
            return pool.get(index);
        }
        return "";
    }

    private static String decodeLaunchMode(int code) {
        switch (code) {
            case 1: return "singleTop";
            case 2: return "singleTask";
            case 3: return "singleInstance";
            case 4: return "singleInstancePerTask";
            default: return "standard";
        }
    }

    private static int calculateBaselineRisk(DiscoveredDeepLink item) {
        int score = 15;
        if (item.isCustomScheme()) score += 30; // Custom schemes have no ownership verification
        if (item.isExported()) score += 20;
        if (item.isBrowsable()) score += 15;
        if (!item.isAutoVerify() && !item.isCustomScheme()) score += 25; // HTTP/HTTPS without autoVerify
        return Math.min(100, score);
    }

    private static class DataTag {
        String scheme;
        String host;
        String port;
        String path;
        String pathPrefix;
        String pathPattern;
    }
}
