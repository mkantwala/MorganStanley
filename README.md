# Vulnerability Tracker API


## 🚀 Overview

The **Vulnerability Tracker API** is a robust backend application built with **FastAPI** and **Python**, designed to empower Python developers in managing and monitoring vulnerabilities within their application's dependencies. This API simplifies the process of ensuring application security and reliability by providing comprehensive tools for dependency scanning and vulnerability tracking.

This project was developed as a **practical exercise** to showcase backend development skills, API design principles, and optimization techniques for the Interview assignment at Morgan Stanley. 

## ✨ Features

This API provides a comprehensive set of features to help you manage your application's vulnerabilities:

  * **🔒 User Authentication:**
      * Securely manage user sessions with **JWT (JSON Web Token) based authentication** for login and logout functionalities.
  * **📦 Application Management:**
      * **Create Applications:**  Effortlessly register new Python applications by providing a name, description, and uploading a `requirements.txt` file.
      * **Retrieve Applications:**  List all applications associated with your user account, with clear identification of vulnerable applications.
      * **Update Applications:** Modify application details and requirements as your project evolves.
      * **Delete Applications:** Remove applications that are no longer needed.
  * **🕸️ Dependency Tracking:**
      * **Get Application Dependencies:**  Fetch a detailed list of dependencies for any registered application, including vulnerability status for each dependency.
      * **Get All Dependencies:**  List all dependencies tracked across all of your applications, highlighting any vulnerable dependencies.
      * **Get Specific Dependency Details:**  Obtain in-depth information about a specific dependency, including its usage across your applications and a comprehensive list of associated vulnerabilities.
  * **🚦 Rate Limiting:**
      * Implements **rate limiting** to protect the API from abuse and ensure fair usage by restricting the number of requests within a defined time window.
  * **💨 Caching:**
      * Leverages **caching mechanisms** to significantly improve API performance and reduce latency by storing and quickly retrieving frequently accessed vulnerability data, minimizing redundant calls to the external [OSV API](https://osv.dev/).
  * **🔍 LLM-Powered Library Suggestions (Experimental):**
      * Includes a basic, **demonstration-level LLM-based search agent**.
      * Provides suggestions for alternative Python libraries, offering enhanced functionality discovery (currently unoptimized and for experimental purposes).
  * **🪵 Logging & Error Handling:**
      * Enhanced utility functions with robust **error handling** to gracefully manage unexpected situations.
      * Comprehensive **logging** implemented for improved debuggability and monitoring of API operations.
      * **Proper HTTP Response Codes** are returned to ensure clear communication of API status.
  
## 🛠️ Technical Requirements & Design

  * **Backend Framework:** Built using **FastAPI** and **Python**, ensuring a modern, high-performance, and developer-friendly API.
  * **Vulnerability Data Source:** Integrates with the [**Open Source Vulnerabilities (OSV) API**](https://osv.dev/) to reliably fetch vulnerability information for Python package dependencies.
  * **Data Storage:** Employs **in-memory data storage** for application and dependency information, simplifying setup and focusing on API logic.
  * **Version Control:**  Maintained with **meaningful commit messages** and a **clear commit history** in a Git repository, reflecting a professional development workflow.
  * **Optimization Focus:** Designed with **API response time optimization** in mind, incorporating caching strategies to minimize latency and external API calls.


## 🚀 Installation & Setup

Get started with the Vulnerability Tracker API in a few simple steps:

1.  **Clone the Repository:**

    ```bash
    git clone [https://github.com/mkantwala/MorganStanley.git](https://www.google.com/search?q=https://github.com/mkantwala/MorganStanley.git)
    cd vulnerability-tracker-api
    ```

2.  **Create a Virtual Environment (Recommended):**

    ```bash
    python -m venv venv
    ```

3.  **Activate the Virtual Environment:**

      * **On Linux/macOS:**
        ```bash
        source venv/bin/activate
        ```
      * **On Windows:**
        ```bash
        venv\Scripts\activate
        ```

4.  **Install Dependencies:**

    ```bash
    pip install -r requirements.txt
    ```

5.  **Run the Application:**

    ```bash
    uvicorn main:app --reload
    ```

    Visit `http://127.0.0.1:8000/docs` or `http://localhost:8000/docs` in your browser to access the interactive API documentation (Swagger UI).

## Documentation

[//]: # (*   [Detailed Documentation]&#40;docs/detailed_usage.md&#41;)
*   [API Reference](docs/api-reference.md)
*   [Release Notes](RELEASE_NOTES.md)


```
