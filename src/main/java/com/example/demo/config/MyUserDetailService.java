package com.example.demo.config;


import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.example.demo.model.Customer;
import com.example.demo.model.CustomerPrinciple;
import com.example.demo.repo.CustomerRepository;

import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@Service
public class MyUserDetailService implements UserDetailsService{

    private final CustomerRepository customerRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        System.out.println("Customer UserDetailSERVICE REACHEDDDDDDDDDDDD>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>");
        Customer customer = customerRepository.findByUsername(username).orElseThrow(()->{
            throw new UsernameNotFoundException("CAnnot find UserNAME In th repo");
        });
        System.out.println("CUSTOMERPRINCIPLE ISSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSS - ---------------------------------------> "+new CustomerPrinciple(customer));
        return new CustomerPrinciple(customer);
    }
    
}
