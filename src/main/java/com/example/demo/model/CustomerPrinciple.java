package com.example.demo.model;

import java.util.Collection;
import java.util.stream.Collectors;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import lombok.ToString;

@ToString
public class CustomerPrinciple implements UserDetails{
    
    Customer customer;
    
    public CustomerPrinciple(Customer customer) {
        System.out.println("Customer to be entered to CustomerPrinciple issssssssss = "+ customer);
        this.customer = customer;
    }


    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return customer.getAuthorities().stream().map(auth -> new SimpleGrantedAuthority(auth.getAuthorityName())).collect(Collectors.toList());
    }

    @Override
    public String getPassword() {
        return customer.getPassword();
    }

    @Override
    public String getUsername() {
        return customer.getUsername();
    }
    
}
