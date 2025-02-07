package com.devsuperior.demo.services;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.devsuperior.demo.entities.Role;
import com.devsuperior.demo.entities.User;
import com.devsuperior.demo.projections.UserDetailsProjection;
import com.devsuperior.demo.repositories.UserRepository;

@Service
public class UserService implements UserDetailsService {

  @Autowired
  private UserRepository userRepository;

  @Override
  public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
    List<UserDetailsProjection> list = userRepository.searchUserAndRolesByEmail(username);
    if (list.isEmpty())
      throw new UsernameNotFoundException("User not found!");

    User user = new User();
    user.setEmail(username);
    user.setPassword(list.get(0).getPassword());
    list.forEach(role -> user.addRole(new Role(role.getRoleId(), role.getAuthority())));

    return user;
  }

}
