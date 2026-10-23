# Contributing to IntentWatch

We welcome contributions to **IntentWatch — Android Deep-Link Hijacking & Intent Security Analyzer**!

## How to Contribute

1. **Fork the Repository** on GitHub.
2. **Create a Feature Branch**:
   ```bash
   git checkout -b feature/my-security-check
   ```
3. **Open the Project in Android Studio**:
   - Open the root `IntentWatch` directory.
   - Ensure you are using JDK 17.
   - Sync Gradle.
4. **Run Unit Tests**:
   ```bash
   ./gradlew testDebugUnitTest
   ```
5. **Commit Your Changes**:
   ```bash
   git commit -m "feat(scanner): add new URI scheme detection pattern"
   ```
6. **Push to the Branch & Open a Pull Request**.

## Code Standards
- Written in clean, readable Java (API level 26+ compatible).
- Document important security checks, intent resolution behaviors, and potential platform restrictions with comments.
- Maintain Material Design 3 guidelines for cybersecurity interfaces.
