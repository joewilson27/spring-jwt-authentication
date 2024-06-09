package com.jwtauth.app.security.jwt;

import java.io.IOException;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import com.jwtauth.app.security.services.UserDetailsServiceImpl;


/**
 * Let’s define a filter that executes once per request. So we create AuthTokenFilter class that extends OncePerRequestFilter and override doFilterInternal() method.
 * 
 * OncePerRequestFilter makes a single execution for each request to our API. It provides a doFilterInternal() method that we will implement parsing & validating JWT, 
 * loading User details (using UserDetailsService), checking Authorization (using UsernamePasswordAuthenticationToken).
 */

public class AuthTokenFilter extends OncePerRequestFilter {
  
  @Autowired
  private JwtUtils jwtUtils;

  @Autowired
  private UserDetailsServiceImpl userDetailsService;

  private static final Logger logger = LoggerFactory.getLogger(AuthTokenFilter.class);

  @Override
  protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
      throws ServletException, IOException {
    try {
      String jwt = parseJwt(request); // will return token jwt
      if (jwt != null && jwtUtils.validateJwtToken(jwt)) {
        String username = jwtUtils.getUsernameFromJwtToken(jwt);

        UserDetails userDetails = userDetailsService.loadUserByUsername(username);
        // UsernamePasswordAuthenticationToken gets {username, password} from login Request, AuthenticationManager will use it to authenticate a login account.
        UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
        authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

        SecurityContextHolder.getContext().setAuthentication(authentication);
      }
    } catch (Exception e) {
      logger.error("Cannot set user authentication: {}", e);
    }

    filterChain.doFilter(request, response);
  }

  private String parseJwt(HttpServletRequest request) {
    String headerAuth = request.getHeader("Authorization");

    if (StringUtils.hasText(headerAuth) && headerAuth.startsWith("Bearer ")) {
      return headerAuth.substring(7, headerAuth.length());
    }

    return null;
  }

}

/**
 * What we do inside doFilterInternal():
– get JWT from the Authorization header (by removing Bearer prefix)
– if the request has JWT, validate it, parse username from it
– from username, get UserDetails to create an Authentication object
– set the current UserDetails in SecurityContext using setAuthentication(authentication) method.

After this, everytime you want to get UserDetails, just use SecurityContext like this:
UserDetails userDetails =
	(UserDetails) SecurityContextHolder.getContext().getAuthentication().getPrincipal();

// userDetails.getUsername()
// userDetails.getPassword()
// userDetails.getAuthorities()
 */
