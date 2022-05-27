package com.rc.springsecurity.model;

import java.util.Set;
import lombok.Data;

@Data
public class SignUpRequest {
  private String username;
  private String password;
  private String email;
  private Set<String> roles;
}
