# Third-Party Licenses

VerityFlux Enterprise uses the following third-party components. This document
provides attribution and license information as required by each project.

---

## Core Dependencies

### FastAPI
- **License**: MIT
- **Source**: https://github.com/tiangolo/fastapi
- **Copyright**: Copyright (c) 2018 Sebastián Ramírez

```
MIT License

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

### SQLAlchemy
- **License**: MIT
- **Source**: https://github.com/sqlalchemy/sqlalchemy
- **Copyright**: Copyright (c) 2005-2024 Michael Bayer and contributors

```
MIT License

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction...
```

---

### Pydantic
- **License**: MIT
- **Source**: https://github.com/pydantic/pydantic
- **Copyright**: Copyright (c) 2017-2024 Samuel Colvin and other contributors

---

### PyJWT
- **License**: MIT
- **Source**: https://github.com/jpadilla/pyjwt
- **Copyright**: Copyright (c) 2015-2022 José Padilla

---

### Passlib
- **License**: BSD
- **Source**: https://passlib.readthedocs.io/
- **Copyright**: Copyright (c) 2008-2020 Assurance Technologies, LLC

---

### Alembic
- **License**: MIT
- **Source**: https://github.com/sqlalchemy/alembic
- **Copyright**: Copyright (c) 2009-2024 Michael Bayer

---

## Optional Tool Integrations

The following tools are **NOT bundled** with VerityFlux. They are called via
subprocess or public API when installed by the user. VerityFlux does not
redistribute any code from these projects.

### IBM Adversarial Robustness Toolbox (ART)
- **License**: MIT
- **Source**: https://github.com/Trusted-AI/adversarial-robustness-toolbox
- **Copyright**: Copyright (c) 2018-2024 IBM Corporation
- **Usage**: Optional external tool for adversarial ML testing
- **Install**: `pip install adversarial-robustness-toolbox`

```
MIT License

Copyright (c) 2018 IBM Corporation

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

### NVIDIA Garak
- **License**: Apache 2.0
- **Source**: https://github.com/NVIDIA/garak
- **Copyright**: Copyright (c) 2023-2024 NVIDIA Corporation
- **Usage**: Optional external tool for LLM vulnerability scanning
- **Install**: `pip install garak`

```
Apache License
Version 2.0, January 2004
http://www.apache.org/licenses/

TERMS AND CONDITIONS FOR USE, REPRODUCTION, AND DISTRIBUTION

1. Definitions.
...

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```

---

### Microsoft PyRIT
- **License**: MIT
- **Source**: https://github.com/Azure/PyRIT
- **Copyright**: Copyright (c) 2024 Microsoft Corporation
- **Usage**: Optional external tool for AI risk identification
- **Install**: `pip install pyrit`

```
MIT License

Copyright (c) 2024 Microsoft Corporation

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

### TextAttack
- **License**: MIT
- **Source**: https://github.com/QData/TextAttack
- **Copyright**: Copyright (c) 2020 QData Lab, University of Virginia
- **Usage**: Optional external tool for NLP adversarial attacks
- **Install**: `pip install textattack`

---

### Guardrails AI
- **License**: Apache 2.0
- **Source**: https://github.com/guardrails-ai/guardrails
- **Copyright**: Copyright (c) 2023-2024 Guardrails AI
- **Usage**: Optional external tool for LLM output validation
- **Install**: `pip install guardrails-ai`

---

### Foolbox
- **License**: MIT
- **Source**: https://github.com/bethgelab/foolbox
- **Copyright**: Copyright (c) 2017-2024 Jonas Rauber
- **Usage**: Optional external tool for adversarial attacks
- **Install**: `pip install foolbox`

---

## Frontend Dependencies

### React
- **License**: MIT
- **Source**: https://github.com/facebook/react
- **Copyright**: Copyright (c) Meta Platforms, Inc. and affiliates

### Tailwind CSS
- **License**: MIT
- **Source**: https://github.com/tailwindlabs/tailwindcss
- **Copyright**: Copyright (c) Tailwind Labs, Inc.

### Lucide Icons
- **License**: ISC
- **Source**: https://github.com/lucide-icons/lucide
- **Copyright**: Copyright (c) 2020-2024 Lucide Contributors

### Recharts
- **License**: MIT
- **Source**: https://github.com/recharts/recharts
- **Copyright**: Copyright (c) 2015-2024 Recharts Group

---

## Python SDK Dependencies

### httpx
- **License**: BSD-3-Clause
- **Source**: https://github.com/encode/httpx
- **Copyright**: Copyright (c) 2019-2024 Encode OSS Ltd.

### tenacity
- **License**: Apache 2.0
- **Source**: https://github.com/jd/tenacity
- **Copyright**: Copyright (c) 2016-2024 Julien Danjou

---

## Database & Infrastructure

### PostgreSQL
- **License**: PostgreSQL License (similar to MIT)
- **Source**: https://www.postgresql.org/
- **Usage**: Recommended production database

### Redis
- **License**: BSD-3-Clause (Redis Source Available License for v7+)
- **Source**: https://redis.io/
- **Usage**: Optional caching and rate limiting backend

### Docker
- **License**: Apache 2.0
- **Source**: https://www.docker.com/
- **Usage**: Container deployment

---

## Notes on Commercial Use

1. **MIT Licensed Components**: Free for commercial use. Keep copyright notices.

2. **Apache 2.0 Licensed Components**: Free for commercial use. Keep copyright
   notices and document modifications if any.

3. **BSD Licensed Components**: Free for commercial use. Keep copyright notices.

4. **Optional Integrations**: VerityFlux does NOT redistribute code from
   optional tools (ART, Garak, PyRIT, TextAttack). Users install these
   separately if needed. This is the "wrapper" approach similar to how
   SonarQube, Snyk, and GitLab integrate external tools.

---

## License Compliance Checklist

- [x] All bundled dependencies are MIT, BSD, or Apache 2.0 licensed
- [x] Copyright notices preserved in this document
- [x] Optional tools are NOT bundled (wrapper approach only)
- [x] No GPL or AGPL dependencies (would require source disclosure)
- [x] No proprietary dependencies without proper licensing

---

## Updates

This document should be updated when:
- New dependencies are added
- Existing dependencies are updated to new major versions
- New optional tool integrations are added

Last Updated: January 2025
