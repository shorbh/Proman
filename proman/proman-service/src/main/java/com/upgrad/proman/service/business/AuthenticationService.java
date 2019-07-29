package com.upgrad.proman.service.business;

import com.upgrad.proman.service.business.JwtTokenProvider;
import com.upgrad.proman.service.dao.UserDao;
import com.upgrad.proman.service.entity.UserAuthTokenEntity;
import com.upgrad.proman.service.entity.UserEntity;
import com.upgrad.proman.service.exception.AuthenticationFailedException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.time.ZonedDateTime;

@Service
public class AuthenticationService {
    @Autowired
    UserDao userDao;
    @Autowired
    PasswordCryptographyProvider passwordCryptographyProvider;
    @Transactional(propagation = Propagation.REQUIRED)
    public UserAuthTokenEntity authenticate(final String username,final String password) throws AuthenticationFailedException{
        UserEntity userEntity = userDao.getUserByEmail(username);
        if(userEntity == null){
            throw new AuthenticationFailedException("ATH-001","Username not found");
        }
        String encrypt = passwordCryptographyProvider.encrypt(password, userEntity.getSalt());
        if(encrypt.equals(userEntity.getPassword())){
            JwtTokenProvider jwtTokenProvider = new JwtTokenProvider(encrypt);
            UserAuthTokenEntity userAuthTokenEntity = new UserAuthTokenEntity();
            userAuthTokenEntity.setUser(userEntity);
            final ZonedDateTime now = ZonedDateTime.now();
            final ZonedDateTime expiredAt = now.plusHours(8);
            userAuthTokenEntity.setAccessToken(jwtTokenProvider.generateToken(userEntity.getUuid(), now,expiredAt));
            userAuthTokenEntity.setLoginAt(now);
            userAuthTokenEntity.setExpiresAt(expiredAt);
            userAuthTokenEntity.setCreatedBy("backend-api");
            userAuthTokenEntity.setCreatedAt(now);
            userDao.createAuthToken(userAuthTokenEntity);
            userEntity.setLastLoginAt(now);
            userDao.updateUser(userEntity);
            return userAuthTokenEntity;
        }
        else{
            throw new AuthenticationFailedException("ATH-002","Password corresponds to given username was incorrect");
        }
    }
}
