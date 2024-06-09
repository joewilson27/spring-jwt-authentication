package com.jwtauth.app.security.services;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.jwtauth.app.entity.User;
import com.jwtauth.app.repository.UserRepository;

/**
 * UserDetailsService interface HAS a method to load User by username and 
 * returns a UserDetails object that Spring Security can use for authentication and validation.
 */

@Service
public class UserDetailsServiceImpl implements UserDetailsService {
  
  @Autowired
  UserRepository userRepository;

  @Override
  @Transactional
  public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
    User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User Not Found with username: " + username));
    
    return UserDetailsImpl.build(user);
  }

  /**
   * In the code above, we get full custom User object using UserRepository, then we build a UserDetails object using static build() method.
   */
}
