package com.gcalsolaro.security.jwt.server.controller;

import java.io.IOException;
import java.util.Arrays;
import java.util.Date;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import com.gcalsolaro.security.jwt.server.constants.SecurityConstants;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

@Controller
@RequestMapping("/api/public")
public class PublicController {

	@GetMapping("/index")
	public String getMessage(HttpServletRequest request, HttpServletResponse response) {
		Cookie cookie = new Cookie(SecurityConstants.TOKEN_HEADER, null);
		cookie.setPath("/");
		cookie.setMaxAge(0);
		response.addCookie(cookie);

		return "index";
	}

	@PostMapping("/redirect")
	public void redirect(HttpServletRequest request, HttpServletResponse response) throws IOException {

		byte[] signingKey = SecurityConstants.JWT_SECRET.getBytes();

		String token = Jwts.builder()
				.signWith(Keys.hmacShaKeyFor(signingKey), SignatureAlgorithm.HS512)
				.setHeaderParam("typ", SecurityConstants.TOKEN_TYPE)
				.setIssuer(SecurityConstants.TOKEN_ISSUER)
				.setAudience(SecurityConstants.TOKEN_AUDIENCE)
				.setSubject("user")
				.setExpiration(new Date(System.currentTimeMillis() + 864000000))
				.claim("rol", Arrays.asList("ROLE_USER"))
				.compact();

		Cookie cookie = new Cookie(SecurityConstants.TOKEN_HEADER, SecurityConstants.TOKEN_PREFIX + token);
		cookie.setPath("/");
		response.addCookie(cookie);

		new DefaultRedirectStrategy().sendRedirect(request, response, "http://localhost:8083/api/private");

	}
}
