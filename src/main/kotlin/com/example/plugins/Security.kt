package com.example.plugins

import io.ktor.auth.*
import io.ktor.util.*
import io.ktor.auth.jwt.*
import com.auth0.jwt.JWT
import com.auth0.jwt.JWTVerifier
import com.auth0.jwt.algorithms.Algorithm
import io.ktor.sessions.*
import io.ktor.application.*
import io.ktor.http.*
import io.ktor.http.auth.*
import io.ktor.response.*
import io.ktor.request.*
import io.ktor.routing.*

fun Application.configureSecurity() {
    val jwtAudience = "example" //environment.config.property("jwt.audience").getString()
    val jwtRealm = "example.com"//environment.config.property("jwt.realm").getString()
    val jwtIssuer = "example.com" //environment.config.property("jwt.domain").getString()
    data class JwtToken(val token:String)
    authentication {
        jwt {

            //configure jwt
            realm = jwtRealm
            verifier(
                JWT
                    .require(Algorithm.HMAC256("secret"))
                    .withAudience(jwtAudience)
                    .withIssuer(jwtIssuer)
                    .build()
            )
            //validate if a request comes in(after authHeader call)
            validate { credential ->
                if (credential.payload.audience.contains(jwtAudience)) JWTPrincipal(credential.payload) else null
            }
            //use cookie as jwt token
            authHeader {
                val oldHeader = it.request.parseAuthorizationHeader()
                val jwt = it.sessions.get<JwtToken>()
                jwt?.token?.let { token ->
                    HttpAuthHeader.Single(oldHeader?.authScheme ?: "Bearer", token)
                } ?: oldHeader
            }
        }
    }
    install(Sessions) {
        cookie<JwtToken>("JWT") {
            cookie.extensions["SameSite"] = "lax"
        }
    }

    routing {
        get("/login"){
            //generate token
            val token = JWT.create()
                .withAudience(jwtAudience)
                .withIssuer(jwtIssuer)
                .sign(Algorithm.HMAC256("secret"))
            //put new token into cookies (this should be safer if you split the token into two parts eg. 2 cookies)
            call.sessions.set(JwtToken(token))
            //redirect user to home page as logged in user ( see authHeader call in jwt confuguration)
            call.respondRedirect("/home")
        }
        authenticate(optional = true) {
            get("/home") {
                val principal = call.principal<JWTPrincipal>()
                //use html as response for connect charset without more code, do not do this in production,
                // use always correct response
                call.respondText(ContentType.Text.Html, HttpStatusCode.OK) { principal?.payload?.issuer ?: "not logged in" }
            }
        }
        authenticate {
            get("/logout"){
                //destroy cookie
                call.sessions.clear("JWT")
            }
        }
    }
}
