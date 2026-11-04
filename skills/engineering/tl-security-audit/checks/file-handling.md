---
id: file-handling
title: File upload, download and path handling
owasp: A01
cwe: [CWE-22, CWE-434, CWE-409, CWE-73]
languages: [csharp, js, python, java, go, php, ruby]
triggers: ['(?i)IFormFile|multer|upload|download|sendFile|Path\.Combine|path\.join|FileStream|zip|unzip|extract|attachment']
---
# Files

- **Path traversal:** user input in file paths; check the resolved full path stays under the base
  directory (not just `Contains("..")`).
- **Uploads:** type validated by content (magic bytes) and allow-listed extension; size limits;
  stored outside the web root or in object storage with random names; served with
  `Content-Disposition: attachment` and correct content type; no execution permissions;
  SVG/HTML uploads served from a separate domain (stored XSS).
- **Archives:** zip slip (entry names with `../`), zip bombs (no size/ratio limits).
- **Downloads/exports:** authorization on the file id (IDOR), signed URLs with short expiry.
- **Image/document processing:** ImageMagick/Ghostscript/LibreOffice on untrusted files — sandboxed?
