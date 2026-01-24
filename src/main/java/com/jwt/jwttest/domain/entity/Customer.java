package com.jwt.jwttest.domain.entity;

import jakarta.persistence.*;
import lombok.Data;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;

import java.time.LocalDateTime;
import java.util.Set;
import java.util.UUID;

import static jakarta.persistence.FetchType.EAGER;

@Table(name = "customer")
@Entity
@Data
public class Customer {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String uuid;
    private String firstName;
    private String secondName;
    private String lastName;
    private String email;
    private String password;
    private String phoneNumber;
    private String verificationToken;
    private Boolean verified = false;
    private Boolean enabled = true;
    private Integer tokenVersion = 0;

    @CreatedDate
    @Column(updatable = false)
    private LocalDateTime createdAt;

    @LastModifiedDate
    private LocalDateTime updatedAt;

    @OneToMany(mappedBy = "customer", fetch = EAGER, cascade = CascadeType.ALL)
    private Set<Authority> authorities;

    @PrePersist
    public void prePersist() {
        this.uuid = UUID.randomUUID().toString();
    }
}
