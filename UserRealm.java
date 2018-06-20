package com.sdaj.security;


import com.sdaj.constans.Constants;
import com.sdaj.enumtype.UserStatus;
import com.sdaj.model.Role;
import com.sdaj.model.User;
import com.sdaj.service.role.RoleService;
import com.sdaj.service.user.UserService;
import org.apache.shiro.authc.*;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.util.ByteSource;
import org.springframework.stereotype.Service;

import javax.annotation.Resource;
import java.util.HashSet;
import java.util.Set;

/**
 * 继承了AuthenticatingRealm  注入  private CredentialsMatcher credentialsMatcher;
 *
 * @author zs
 */
@Service
public class UserRealm extends AuthorizingRealm {

    @Resource
    private UserService userService;

    @Resource
    private RoleService roleService;

    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {

        User user = (User) principals.getPrimaryPrincipal();

        SimpleAuthorizationInfo authorizationInfo = new SimpleAuthorizationInfo();
        Set<String> roles = new HashSet<String>();//必须String ,因为hasRole等标签是  匹配String的
        //不根据user中的role来判断角色，是根据role对应的type 来区分的

        Integer roleId = user.getRole();
        Role role = roleService.findById(roleId);
        roles.add(String.valueOf(role.getType()));
        authorizationInfo.setRoles(roles);//查询用户的角色信息
        //我们系统暂时没有 到资源粒度的
        //authorizationInfo.setStringPermissions(userService.findPermissions(user.getUsername()));

        return authorizationInfo;
    }

    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {

        String username = (String) token.getPrincipal();

        User user = userService.findByUsername(username);

        if (user == null) {
            throw new UnknownAccountException();//没找到帐号
        }

        if (UserStatus.ENABLE.getStatus() != user.getStatus().intValue() && UserStatus.IMPORT.getStatus() != user.getStatus()) {
            throw new LockedAccountException(); //帐号锁定 或  未启用
        }

        //交给AuthenticatingRealm使用CredentialsMatcher进行密码匹配
        SimpleAuthenticationInfo authenticationInfo = new SimpleAuthenticationInfo(
                user,//Object可以写入自己需要的对象 principals.getPrimaryPrincipal()就是这里取出来的对象
                user.getPassword(), //密码
                ByteSource.Util.bytes(Constants.SALT),
                getName()  //realm name
                /*{
                this.principals = new SimplePrincipalCollection(principal, realmName);
                this.credentials = hashedCredentials;
                this.credentialsSalt = credentialsSalt;
              }*/

        );
        return authenticationInfo;
    }

    @Override
    public void clearCachedAuthorizationInfo(PrincipalCollection principals) {
        super.clearCachedAuthorizationInfo(principals);
    }

    @Override
    public void clearCachedAuthenticationInfo(PrincipalCollection principals) {
        super.clearCachedAuthenticationInfo(principals);
    }

    @Override
    public void clearCache(PrincipalCollection principals) {
        super.clearCache(principals);
    }

    public void clearAllCachedAuthorizationInfo() {
        getAuthorizationCache().clear();
    }

    public void clearAllCachedAuthenticationInfo() {
        getAuthenticationCache().clear();
    }

    public void clearAllCache() {

        clearAllCachedAuthenticationInfo();

        clearAllCachedAuthorizationInfo();
    }

}
