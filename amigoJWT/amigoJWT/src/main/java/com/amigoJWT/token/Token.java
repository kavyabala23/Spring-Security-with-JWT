package com.amigoJWT.token;

import com.amigoJWT.user.User;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Entity
public class Token {
    @Id
    @GeneratedValue
    private Integer id;
    private  String token;
    @Enumerated(EnumType.STRING)
    private TokenType tokenType = TokenType.BEARER;;
    private  boolean expired;
    //in case u want to revoke manually or for eg if you want to implemenet a mechanism when you want to restart your application or you start your server you want to revoke all the tokens so we are creatng flags for that
    //revoked- token entity
    private  boolean revoked;

    @ManyToOne
    @JoinColumn(name ="user_id")
    private User user;

}
