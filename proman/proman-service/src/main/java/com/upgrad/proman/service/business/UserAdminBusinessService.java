package com.upgrad.proman.service.business;

import com.upgrad.proman.service.dao.UserDao;
import com.upgrad.proman.service.entity.RoleEntity;
import com.upgrad.proman.service.entity.UserAuthTokenEntity;
import com.upgrad.proman.service.entity.UserEntity;
import com.upgrad.proman.service.exception.ResourceNotFoundException;
import com.upgrad.proman.service.exception.UnauthorizedException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

@Service
public class UserAdminBusinessService {

    @Autowired
    UserDao userDao;
    @Autowired
    PasswordCryptographyProvider passwordCryptographyProvider;
    public UserEntity getUser(final String userUuid,final  String authorizationToken) throws ResourceNotFoundException,UnauthorizedException{

        UserAuthTokenEntity userAuthTokenEntity = userDao.getUserAuthToken(authorizationToken);
        RoleEntity role = userAuthTokenEntity.getUser().getRole();
        if(role.getUuid()==101){
            UserEntity userEntity = userDao.getUser(userUuid);
            if(userEntity == null){
                throw new ResourceNotFoundException("c-101","can not find user");
            }
            return userEntity;
        }
        throw new UnauthorizedException("ATH-002","user is unauthorized");

    }
    @Transactional(propagation = Propagation.REQUIRED)
    public UserEntity createUser(final UserEntity userEntity){
        String password = userEntity.getPassword();
        if(password == null){
            password = "Rahul@123";
        }
        String[] encrypt = passwordCryptographyProvider.encrypt(userEntity.getPassword());
        userEntity.setSalt(encrypt[0]);
        userEntity.setPassword(encrypt[1]);
        return userDao.createUser(userEntity);
    }
}
