## Release History - MorganStanley Repository

This document outlines the release history for the [**MorganStanley**](https://github.com/mkantwala/MorganStanley.git) repository.

-----

### v0.1.1 <img src="https://img.shields.io/badge/Version-0.1.1-blue" alt="Version 0.1.1 Badge"> <Badge type="info">Latest</Badge>

**Enhancements:**

  * **Improved Code Readability:** Added comprehensive documentation strings and comments to functions, enhancing code readability and maintainability.

**TODO:**

  * **Endpoint Test Cases:** Creation of test cases for all API endpoints is pending to ensure robust functionality and prevent regressions.

-----

### v0.1.0 <img src="https://img.shields.io/badge/Version-0.1.0-blue" alt="Version 0.1.0 Badge"> - [`28c1b87cbf46bb8ca4a945659e52840d73fb883c`]([https://www.google.com/url?sa=E&source=gmail&q=https://github.com/mkantwala/MorganStanley.git/commit/28c1b87cbf46bb8ca4a945659e52840d73fb883c](https://www.google.com/url?sa=E&source=gmail&q=https://github.com/mkantwala/MorganStanley.git/commit/28c1b87cbf46bb8ca4a945659e52840d73fb883c))

**Key Features:**

  * **Enhanced Error Handling:** Implemented robust error handling mechanisms to gracefully manage unexpected situations.
  * **Logging Integration:** Introduced logging to track application behavior, aid in debugging, and monitor system health.
  * **Proper Response Codes:** Ensured all API endpoints return appropriate HTTP response codes, facilitating better client-side error handling and integration.
  * **Modular Utilis Functions:** Refactored utility functionalities into dedicated functions within the `utilis` module, promoting code modularity and streamlined operations.
      * `check_rate_limit`
      * `fetch_vulnerability`
      * `fetch_package_info`
      * `fetch_vulns`

-----

### v0.0.3 <img src="https://img.shields.io/badge/Version-0.0.3-blue" alt="Version 0.0.3 Badge">

**Bug Fixes:**

  * **Application Dependency Vulns:** Addressed an issue where vulnerability lists were not correctly associated with specific application dependencies.
  * **Cache Management:** Resolved a critical caching problem that caused user application lists to be incorrectly saved across different user sessions. The cache is now scoped to individual user applications.

**New Features:**

  * **Modular Utilis Functions:**  Core functionalities for vulnerability checking and data retrieval have been modularized into reusable functions within the `utilis` module for improved code organization and maintainability.
      * `check_rate_limit`
      * `fetch_vulnerability`
      * `fetch_package_info`
      * `fetch_vulns`
  * **Experimental LLM Search Agent:** Introduced a rudimentary, demonstration-level Large Language Model (LLM) search agent. This agent provides alternative library suggestions for a given library, showcasing potential for future extended functionality.  *(Note: This feature is currently unoptimized and for proof-of-concept purposes.)*

-----

### v0.0.2 <img src="https://img.shields.io/badge/Version-0.0.2-blue" alt="Version 0.0.2 Badge"> - [`b2fdef28826c928153854389eff27ccaad801ef0`]([https://www.google.com/url?sa=E&source=gmail&q=https://github.com/mkantwala/MorganStanley.git/commit/b2fdef28826c928153854389eff27ccaad801ef0](https://www.google.com/url?sa=E&source=gmail&q=https://github.com/mkantwala/MorganStanley.git/commit/b2fdef28826c928153854389eff27ccaad801ef0))

**Bug Fixes:**

  * **`process_file` Vulnerability Counting:**  Corrected an issue in the `process_file` function that prevented accurate vulnerability counts when vulnerabilities already existed in the database.
  * **Declaration Cleanup:** Removed unnecessary variable declarations, improving code cleanliness.
  * **`update_file` Functionality:**  Significantly improved the `update_file` function to correctly manage application updates, including:
      * Proper updating of application details.
      * Accurate management of application dependencies.
      * Correct handling of vulnerabilities – ensuring both addition of new vulnerabilities and removal of vulnerabilities that are no longer associated with any application, ensuring data integrity and efficient database management.

-----

### v0.0.1 <img src="https://img.shields.io/badge/Version-0.0.1-blue" alt="Version 0.0.1 Badge"> - [`a3a70b456f331c5c87ff383d0647d61d4bfceb5d`]([https://www.google.com/url?sa=E&source=gmail&q=https://github.com/mkantwala/MorganStanley.git/commit/a3a70b456f331c5c87ff383d0647d61d4bfceb5d](https://www.google.com/url?sa=E&source=gmail&q=https://github.com/mkantwala/MorganStanley.git/commit/a3a70b456f331c5c87ff383d0647d61d4bfceb5d))

**Initial Release:**

  * **Core Functionality:**  This commit marks the initial release of the MorganStanley repository, establishing the fundamental codebase and project structure.

-----

