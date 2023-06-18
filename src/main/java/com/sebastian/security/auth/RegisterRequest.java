package com.sebastian.security.auth;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;


public record RegisterRequest (String firstname, String lastname, String email, String password) {
}
