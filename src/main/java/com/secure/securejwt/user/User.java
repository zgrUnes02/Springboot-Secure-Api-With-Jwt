package com.secure.securejwt.user;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;

@Data
@Entity
@Table(name = "users")
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class User implements UserDetails {
    @Id
    @Column(name = "id" , updatable = false , unique = true)
    @GeneratedValue(generator = "user_generator" , strategy = GenerationType.AUTO)
    @SequenceGenerator(name = "user_generator" , sequenceName = "user_sequence" , initialValue = 1 , allocationSize = 1)
    private Integer id ;

    @Column(name = "first_name" , updatable = true , nullable = false)
    private String firstName ;

    @Column(name = "family_name" , updatable = true , nullable = false)
    private String familyName ;

    @Column(name = "email" , updatable = true , nullable = false , unique = true)
    private String email ;

    @Column(name = "password" , updatable = true , nullable = false)
    private String password ;

    @Enumerated(EnumType.STRING)
    private Role role ;

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of(new SimpleGrantedAuthority(role.name())) ;
    }

    @Override
    public String getPassword() {
        return password ;
    }

    @Override
    public String getUsername() {
        return email ;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true ;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true ;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true ;
    }

    @Override
    public boolean isEnabled() {
        return true ;
    }
}
