### ✍️ About the service
**Gateway** - is a part of the Appeals Project.  
It handles redirecting users request to the services.
---
### ⚒️ Tech
- Java 21
- Spring Cloud Gateway
- Maven
- Docker
- Spring Security

---
### ⚙️ Project Structure
``` bash
├── Dockerfile
├── compose.yaml
├── pom.xml
├── src
│   ├── main
│   │   ├── java
│   │   │   └── gateway
│   │   │       └── security
│   │   └── resources
│   └── test
```

---
### 🧩 Start project

``` bash
git clone https://github.com/pepegazxc/Gateway-appealsProject.git
cd Gateway-appealsProject
```

Then your must create .env file:
``` bash
touch .env
```

And then fill it (example data):
``` file
JWT_KEY=key
```

And then run the containers:
``` bash
docker-compose up -d
```

---
### 🔙 Back to navigate repository

Navigate repository: [AppealsProject](https://github.com/pepegazxc/Appeals-Project.git)
