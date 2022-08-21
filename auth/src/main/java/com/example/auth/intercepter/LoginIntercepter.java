package com.example.auth.intercepter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.exceptions.TokenExpiredException;
import com.auth0.jwt.interfaces.DecodedJWT;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.servlet.handler.HandlerInterceptorAdapter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@Slf4j
@Component
public class LoginIntercepter extends HandlerInterceptorAdapter {

    /**
     * 返回true, 表示不拦截，继续往下执行
     * 返回false, 抛出异常，不再往下执行
     * @param request
     * @param response
     * @param handler
     * @return
     * @throws Exception
     */
    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        String token = request.getHeader("token");
        if(StringUtils.isEmpty(token)){
            throw new RuntimeException("token is error");
        }
        Algorithm algorithm = Algorithm.HMAC256("abc");
        JWTVerifier verifier = JWT.require(algorithm)
                .build();
        try{
            DecodedJWT decodedJWT = verifier.verify(token);
            request.setAttribute("username",decodedJWT.getClaim("username").toString());
        }catch (TokenExpiredException e){
            log.error("token过期：{}",e.getExpiredOn());
            throw new RuntimeException("token过期");
        }catch (JWTVerificationException e){
            log.error("解码失败，token错误");
            throw new RuntimeException("解码失败，token错误");
        }
        return true;
    }
}
