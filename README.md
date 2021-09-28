# Page with Extra MFA Protection using Spring Boot
  
This repository contains an example Spring Boot application that is used to demonstrate how specific routes can add extra MFA protection. 


**Prerequisites:** 
* [Java 8+](https://adoptopenjdk.net/)

> [Okta](https://developer.okta.com/) has Authentication and User Management APIs that reduce development time with instant-on, scalable user infrastructure. Okta's intuitive API and expert support make it easy for developers to authenticate, manage, and secure users and roles in any application.

* [Getting Started](#getting-started)
* [Links](#links)
* [Help](#help)
* [License](#license)

## Spring Boot Example

To install this example, run the following commands:

```bash
git clone https://github.com/emanor-okta/spring-protected-page-mfa.git
cd spring-protected-page-mfa
```

### Create a Web Application in Okta

Log in to your Okta Developer account (or [sign up](https://developer.okta.com/signup/) if you don't have an account).

1. From the **Applications** page, choose **Add Application**.
2. On the Create New Application page, select **Web**.
3. Give your app a memorable name, add `http://localhost:8080/login/oauth2/code/okta` as a Login redirect URI, select **Refresh Token** (in addition to **Authorization Code**), and click **Done**.
4. From the **Applications** page, choose **Add Application**.
5. On the Create New Application page, select **Web**.
6. Give your app the same name as above with '-mfa' appended, add `http://localhost:8080/login/oauth2/code/oktamfa` and `http://localhost:8080/admin-callback` as a Login redirect URIs. Select **Authorization Code** and **Implicit Hybrid** (with **Allow Access** and **ID** Tokens). Click **Done**.
7. Edit the app just created, under the **Sign On** tab add a rule for **Sign On Policy**. Give the rule a name, under **Actions** -> **Access** keep **Allowed** and select **Prompt for Factor**. Select **Every sign on**. Keep the rest of the defaults and save.
8. For each application that was created copy down the **Client ID** and **Client secret**.
9. From the **Security** -> **API** page select the Authorization Server to be used (**default** is good for this). Select **scopes** and **Add Scope**. For **Name**, **Display phrase**, and **Description** enter **admin**, then **save**.
10. If a scope named **groups** does not already exist add a new one using **groups** for **Name**, **Display phrase**, and **Description**.
11. Select **claims** tab and if a claim named **groups** does not already exist click **Add Claim**. Name should be **groups**, for **include in token type** select **Access Always**. For **value type** select **groups**. For **filter** choose **matches regex** with a vlaue of `.*`. For **include in** select **groups**, then **save**.
12. Selete the **settings** tab and make note of the **issuer** and **audience**.

Edit the `application.yml` file.

```yaml
spring:
  security:
    oauth2:
      client:
        provider:
          okta:
            issuer-uri: https://{OKTA_ORG}/oauth2/{AUTHORIZATION_SERVER}
          oktamfa:
            issuer-uri: https://{OKTA_ORG}/oauth2/{AUTHORIZATION_SERVER}
            audience: {AUDIENCE}  # not an actual Spring property
        registration:
          okta:
            client-id: {CLIENT_ID}
            client-secret: {CLIENT_SECRET}
            scope: openid,profile,email,groups
          oktamfa:
            client-id: {CLIENT_ID}
            client-secret: {CLIENT_SECRET}
            scope: openid,admin,profile,email,groups
```

For the properties under `okta` use the values from the first app (app1) created.
For the properties under `oktamfa` use the values from the second app (app2) created.

* Create a group in Okta named `admin`
* Select a couple of test users and add both to **app1**
* Select one of the users and add them to the `admin` group and to **app2**

Then, run the project with `./mvnw spring-boot:run`. You should be able to navigate to `http://localhost:8080` to see the application.

* Logging in with the user not part of the admin group should only present a `profile` button.
* Logging in with the user that is part of the admin group will also present two admin buttons ([Admin](#admin) and [Admin2](#admin2)). Selecting either will prompt for MFA the first time.


## Admin

This will use Springs built in OAuth2 Security to authorize the user against `app2`. Springs call-back handler will be used, and after authorization the Spring **Authentication** will now be for `app2`, not `app1` which was originally logged into. The **Granted Authorties** will now contain the admin scope.

## Admin2

This will generate a manual **/authorize** request to `app2` and will use a manual call-back hanlder which will verify the **access_token** returned (this app was setup as implicit). Once the **audience**/**scope** are manually validated with the [Okta JWT Verifier](https://github.com/okta/okta-jwt-verifier-java), the Spring Authentication will be recreated adding the scope admin to the **Granted Authorities**. The Spring **Authentication** will still be for `app1`, not `app2`.

*Instead of doing this redirect to a second application with MFA enabled, the [Okta Factors API](https://developer.okta.com/docs/reference/api/authn/#verify-factor) could also be used. Much of the functionality to interact with the API can be found in the [Java Management SDK](https://github.com/okta/okta-sdk-java#verify-a-factor).*


## Links

These examples uses the following open source libraries:
 
* [Spring Boot](https://spring.io/projects/spring-boot)
* [Spring Security](https://spring.io/projects/spring-security)
* [OpenJDK](https://openjdk.java.net/)

## Help

Please add an Issue.

## License

Apache 2.0, see [LICENSE](LICENSE).

