<br>

<h1 align="center">
    Pandorica
</h1>
<br/><br/>

<p align="center">
    <a href="https://surrealdb.com/" target="_blank">
        <img alt="Powered by SurrealDB" src="https://surrealdb.com/static/img/assets/poweredby/light-b406f91aa4604d58dd5635d1f4d9a7b5.png" height="60" />
    </a>
</p>

<h3 align="center">
    A <b>zero-knowledge secure file storage system</b> that uses cutting-edge technologies and security best practices to ensure your data is safe and secure.
</h3>

<h3 align="center" style="color: #ac3232">
    Important: This is a work in progress, and is not ready for production use.
</h3>

<br>

## What is Pandorica?
Pandorica is a secure file storage system that provides zero-knowledge encryption of user files. It is written in Rust and uses [SurrealDB](https://surrealdb.com/) as its underlying database technology. The zero-knowledge encryption technique ensures that only the owner of the files can access them, even if the files are stored on a remote server or in the cloud.

[SurrealDB](https://surrealdb.com/) is a distributed, fault-tolerant, and consistent database technology that provides fast and reliable data storage. It is an ideal choice for Pandorica as it ensures that data is safely stored and can be retrieved quickly when needed.

With Pandorica, users can securely store and manage their files without having to worry about the security of their data. The system allows users to store and retrieve files from any device or location, making it a convenient and reliable choice for file storage.

## Why Pandorica?
1. **Enhanced Security:** Pandorica provides zero-knowledge encryption, which means that user data is encrypted and can only be accessed by the user who owns it. This level of security is not available in many other file storage options.

2. **Open-Source and Trustworthy:** Pandorica is open-source software, which means that its code is available for review by anyone. This increases trust in the system as it ensures that there are no hidden backdoors or vulnerabilities.

3. **Fast and Reliable:** Pandorica uses [SurrealDB](https://surrealdb.com/), which is a fast and reliable database technology. This ensures that data is quickly retrieved when needed, and the system is always available.

4. **Control Over Data:** With Pandorica, users have complete control over their data. They can store and manage their files without the risk of third-party access, ensuring the privacy and security of their data.

5. **No fingerprinting or analytics**: Pandorica doesn't collect any fingerprinting or analytics information about their users, and it **doesn't call home**.

Overall, Pandorica provides enhanced security, is open-source and trustworthy, easy to use, fast and reliable, and gives users complete control over their data. These are all compelling reasons why people may choose Pandorica over other file storage options.

## Features

- **HSM-backed master keys**<br/>The master keys are encrypted using an HSM master key provided by GCP<br/>_In the future, this will be configurable between GCP, AWS, or using Software-only keys_<br/><br/>
- **ChaCha20Poly1305 encryption**<br/>_In the future, more options will be provided_<br/><br/>
- **Argon2id hashing**<br/>_In the future, more options will be provided_<br/><br/>
- **Scrypt key derivation**<br/>_In the future, more options will be provided_<br/><br/>
- **Automatic encryption of sensitive fields, such as `email`**<br/><br/>

## Planned features
- **Multiple storage backends**<br/>Such as GCP, S3, Azure, or local storage<br/><br/>
- **Automatic key rotation**<br/><br/>
- **Batched uploads**<br/><br/>
- **End-to-end encryption**<br/><br/>
- **Secure file sharing options**<br/><br/>
- **Desktop and mobile apps**<br/><br/>

## License
Pandorica is licensed under the [EUPLv1.2 License](https://joinup.ec.europa.eu/collection/eupl/eupl-text-eupl-12).