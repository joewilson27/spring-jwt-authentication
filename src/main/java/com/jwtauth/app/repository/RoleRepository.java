package com.jwtauth.app.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.jwtauth.app.entity.ERole;
import com.jwtauth.app.entity.Role;

@Repository
public interface RoleRepository extends JpaRepository<Role, Long> {
  
  Optional<Role> findByName(ERole name);

}
