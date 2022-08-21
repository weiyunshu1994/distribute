package com.example.auth.controller;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.exceptions.TokenExpiredException;
import com.auth0.jwt.interfaces.DecodedJWT;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpSession;
import java.util.Date;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

@Slf4j
@RestController
@RequestMapping("/api/v1/auth")
public class AuthController {

    @Autowired
    private StringRedisTemplate stringRedisTemplate;

    /**
     * 将信息放入session中，保存在程序运行的容器里，往前端返回JSESSIONID
     * @param username
     * @param password
     * @param session
     * @return
     */
    @GetMapping("/login-session")
    public String login(@RequestParam String username,
                        @RequestParam String password,
                        HttpSession session) {
        session.setAttribute("loginUsername", username);
        session.setAttribute("info1", "信息1");
        session.setAttribute("info2", "信息2");
        session.setAttribute("info3", "信息3");
        return "登录成功";
    }

    /**
     * 携带JSESSIONID, 到容器中查找对应信息放在session中
     * @param session
     * @return
     */
    @GetMapping("/info-session")
    public String info(HttpSession session) {
        return "当前登录的是：" + session.getAttribute("loginUsername");
    }


    /**
     * token和相应信息放在redis当中，返回token
     * @param username
     * @param password
     * @return
     */
    @GetMapping("/login-token")
    public String loginWithToken(@RequestParam String username,
                                 @RequestParam String password) {
        String key = "token_" + UUID.randomUUID();
        stringRedisTemplate.opsForValue().set(key, username, 3600, TimeUnit.SECONDS);
        return key;
    }

    /**
     * 请求中携带token，以token作为key去redis中找到相应内容
     */
    @GetMapping("/info-token")
    public String infoWithToken(@RequestParam String token) {
        return "当前登录的是：" + stringRedisTemplate.opsForValue().get(token);

    }

    /**
     * 将用户信息放在JWT-token中，直接返回给用户
     * @param username
     * @param password
     * @return
     */
    @GetMapping("/login-jwt")
    public String loginWithJwt(@RequestParam String username,
                               @RequestParam String password) {
        Algorithm algorithm = Algorithm.HMAC256("abc");
        String token = JWT.create()
                .withIssuer("auth0")
                .withClaim("username", username)
                .withClaim("password", password)
                .withExpiresAt(new Date(System.currentTimeMillis() + 360000))
                .sign(algorithm);
        return token;
    }

    /**
     * 从jwt-token中解析出相应信息
     * @param token
     * @return
     */
    @GetMapping("/info-jwt")
    public String infoWithJwt(@RequestHeader String token) {
        Algorithm algorithm = Algorithm.HMAC256("abc");
        JWTVerifier verifier = JWT.require(algorithm)
                .build();
        try {
            DecodedJWT decodedJWT = verifier.verify(token);
            return decodedJWT.getClaim("username").toString();
        } catch (TokenExpiredException e) {
            log.error("token过期：{}", e.getExpiredOn());
            return "token过期";
        } catch (JWTVerificationException e) {
            log.error("解码失败，token错误");
            return "解码失败，token错误";
        }
    }

    /**
     * 配置拦截器，在访问接口之前获取用户信息，并放入请求头中
     * @param username
     * @return
     */
    @GetMapping("/address")
    public String address(@RequestAttribute String username) {
        return username;
    }

}
