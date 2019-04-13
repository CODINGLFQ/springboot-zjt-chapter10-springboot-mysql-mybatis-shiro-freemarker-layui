# springboot-zjt-chapter10-springboot-mysql-mybatis-shiro-freemarker-layui
通用的java后台管理系统(权限管理+用户管理+菜单管理)



一.前言
经过前10篇文章，我们已经可以快速搭建一个springboot的web项目；

今天，我们在上一节基础上继续集成shiro框架，实现一个可以通用的后台管理系统；包括用户管理，角色管理，菜单管理三大系统常用管理模块；

二.数据库表准备：
要想实现用户管理+角色管理+菜单管理三大模块，基本上我们常用的解决方案就是如下五个表(sql脚本在最后)：



三.集成shiro和配置
1.添加pom依赖。

<dependency>
            <groupId>org.apache.shiro</groupId>
            <artifactId>shiro-core</artifactId>
            <version>1.4.0</version>
        </dependency>

        <dependency>
            <groupId>org.apache.shiro</groupId>
            <artifactId>shiro-spring</artifactId>
            <version>1.4.0</version>
        </dependency>
 

2.编辑shiro配置类：ShiroConfig.java

package com.zjt.config;

import com.zjt.realm.MyRealm;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.spring.LifecycleBeanPostProcessor;
import org.apache.shiro.spring.security.interceptor.AuthorizationAttributeSourceAdvisor;
import org.apache.shiro.spring.web.ShiroFilterFactoryBean;
import org.apache.shiro.web.mgt.CookieRememberMeManager;
import org.apache.shiro.web.mgt.DefaultWebSecurityManager;
import org.apache.shiro.web.servlet.SimpleCookie;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.LinkedHashMap;
import java.util.Map;

#zs#*
* @Author: Zhaojiatao
* @Description: Shiro配置类
* @Date: Created in 2018/2/8 13:29
* @param 
#fzs#
@Configuration
public class ShiroConfig {

    #zs#*
     * ShiroFilterFactoryBean 处理拦截资源文件问题。
     * 注意：单独一个ShiroFilterFactoryBean配置是或报错的，以为在
     * 初始化ShiroFilterFactoryBean的时候需要注入：SecurityManager
     *
     * Filter Chain定义说明 1、一个URL可以配置多个Filter，使用逗号分隔 2、当设置多个过滤器时，全部验证通过，才视为通过
     * 3、部分过滤器可指定参数，如perms，roles
     *
     #fzs#
    @Bean
    public ShiroFilterFactoryBean shirFilter(SecurityManager securityManager) {
        ShiroFilterFactoryBean shiroFilterFactoryBean = new ShiroFilterFactoryBean();

        // 必须设置 SecurityManager
        shiroFilterFactoryBean.setSecurityManager(securityManager);

        // 如果不设置默认会自动寻找Web工程根目录下的"/login.jsp"页面
        //shiroFilterFactoryBean.setLoginUrl("/login.ftl");

        //配置退出过滤器,其中的具体的退出代码Shiro已经替我们实现了
        shiroFilterFactoryBean.setLoginUrl("/tologin");
        shiroFilterFactoryBean.setUnauthorizedUrl("/tologin");

        // 拦截器.
        Map<String, String> filterChainDefinitionMap = new LinkedHashMap<String, String>();
        //配置记住我或认证通过可以访问的地址(配置不会被拦截的链接 顺序判断)
        filterChainDefinitionMap.put("/static#zs#*", "anon");
        filterChainDefinitionMap.put("/user/login", "anon");
        filterChainDefinitionMap.put("/drawImage", "anon");

        // 配置退出过滤器,其中的具体的退出代码Shiro已经替我们实现了
        filterChainDefinitionMap.put("/admin/user/logout", "logout");


        // <!-- 过滤链定义，从上向下顺序执行，一般将 #zs#*放在最为下边 -->:这是一个坑呢，一不小心代码就不好使了;
        // <!-- authc:所有url都必须认证通过才可以访问; anon:所有url都都可以匿名访问-->
        filterChainDefinitionMap.put("#zs#*", "authc");

        shiroFilterFactoryBean.setFilterChainDefinitionMap(filterChainDefinitionMap);
        return shiroFilterFactoryBean;
}

    @Bean
    public SecurityManager securityManager() {
        DefaultWebSecurityManager securityManager = new DefaultWebSecurityManager();
        // 设置realm.
        securityManager.setRealm(myRealm());

        //注入记住我管理器;
        securityManager.setRememberMeManager(rememberMeManager());


        return securityManager;
    }

    #zs#*
     * 身份认证realm; (这个需要自己写，账号密码校验；权限等)
     * 
     * @return
     #fzs#
    @Bean
    public MyRealm myRealm() {
        MyRealm myRealm = new MyRealm();
        return myRealm;
    }

    #zs#*
     * Shiro生命周期处理器
     * @return
     #fzs#
    @Bean
    public LifecycleBeanPostProcessor lifecycleBeanPostProcessor(){
        return new LifecycleBeanPostProcessor();
    }
    #zs#*
     * 开启Shiro的注解(如@RequiresRoles,@RequiresPermissions),需借助SpringAOP扫描使用Shiro注解的类,并在必要时进行安全逻辑验证
     * 配置以下两个bean(DefaultAdvisorAutoProxyCreator(可选)和AuthorizationAttributeSourceAdvisor)即可实现此功能
     * 不要使用 DefaultAdvisorAutoProxyCreator 会出现二次代理的问题，这里不详述
     * @return
     #fzs#
   #zs# @Bean
    @DependsOn({"lifecycleBeanPostProcessor"})
    public DefaultAdvisorAutoProxyCreator advisorAutoProxyCreator(){
        DefaultAdvisorAutoProxyCreator advisorAutoProxyCreator = new DefaultAdvisorAutoProxyCreator();
        advisorAutoProxyCreator.setProxyTargetClass(true);
        return advisorAutoProxyCreator;
    }#fzs#
    @Bean
    public AuthorizationAttributeSourceAdvisor authorizationAttributeSourceAdvisor(){
        AuthorizationAttributeSourceAdvisor authorizationAttributeSourceAdvisor = new AuthorizationAttributeSourceAdvisor();
        authorizationAttributeSourceAdvisor.setSecurityManager(securityManager());
        return authorizationAttributeSourceAdvisor;
    }





    #zs#*
     * cookie对象;
     * 记住密码实现起来也是比较简单的，主要看下是如何实现的。
     * @return
     #fzs#
    @Bean
    public SimpleCookie rememberMeCookie(){
        System.out.println("ShiroConfiguration.rememberMeCookie()");
        //这个参数是cookie的名称，对应前端的checkbox的name = rememberMe
        SimpleCookie simpleCookie = new SimpleCookie("rememberMe");
        //<!-- 记住我cookie生效时间30天 ,单位秒;-->
        simpleCookie.setMaxAge(259200);
        return simpleCookie;
    }

    #zs#*
     * cookie管理对象;
     * @return
     #fzs#
    @Bean
    public CookieRememberMeManager rememberMeManager(){
        System.out.println("ShiroConfiguration.rememberMeManager()");
        CookieRememberMeManager cookieRememberMeManager = new CookieRememberMeManager();
        cookieRememberMeManager.setCookie(rememberMeCookie());
        return cookieRememberMeManager;
    }





}
 

3.实现自定义MyRealm.java

package com.zjt.realm;

import com.zjt.entity.Tmenu;
import com.zjt.entity.Trole;
import com.zjt.entity.Tuser;
import com.zjt.mapper.TmenuMapper;
import com.zjt.mapper.TroleMapper;
import com.zjt.mapper.TuserMapper;
import com.zjt.mapper.TuserroleMapper;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import tk.mybatis.mapper.entity.Example;

import javax.annotation.Resource;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

#zs#*
 * 自定义Realm
 * @author zjt
 *
 #fzs#
public class MyRealm extends AuthorizingRealm{

    @Resource
    private TuserMapper tuserMapper;
    
    @Resource
    private TroleMapper troleMapper;

    @Resource
    private TuserroleMapper tuserroleMapper;
    
    @Resource
    private TmenuMapper tmenuMapper;

    #zs#*
     * 授权
     #fzs#
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
        String userName=(String) SecurityUtils.getSubject().getPrincipal();

        //User user=userRepository.findByUserName(userName);
        //根据用户名查询出用户记录
        Example tuserExample=new Example(Tuser.class);
        tuserExample.or().andEqualTo("userName",userName);
        Tuser user=tuserMapper.selectByExample(tuserExample).get(0);


        SimpleAuthorizationInfo info=new SimpleAuthorizationInfo();

        //List<Role> roleList=roleRepository.findByUserId(user.getId());
        List<Trole> roleList = troleMapper.selectRolesByUserId(user.getId());

        Set<String> roles=new HashSet<String>();
        if(roleList.size()>0){
            for(Trole role:roleList){
                roles.add(role.getName());
                //List<Tmenu> menuList=menuRepository.findByRoleId(role.getId());
                //根据角色id查询所有资源
                List<Tmenu> menuList=tmenuMapper.selectMenusByRoleId(role.getId());
                for(Tmenu menu:menuList){
                    info.addStringPermission(menu.getName()); // 添加权限
                }
            }
        }
        info.setRoles(roles);
        return info;
    }

    #zs#*
     * 权限认证
                #fzs#
        @Override
        protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
            String userName=(String)token.getPrincipal();
            //User user=userRepository.findByUserName(userName);
            Example tuserExample=new Example(Tuser.class);
            tuserExample.or().andEqualTo("userName",userName);
            Tuser user=tuserMapper.selectByExample(tuserExample).get(0);
            if(user!=null){
                AuthenticationInfo authcInfo=new SimpleAuthenticationInfo(user.getUserName(),user.getPassword(),"xxx");
                return authcInfo;
            }else{
                return null;
            }
    }

}
 

 

4.登录、退出、权限限制

登录：subject.login(token);

退出：SecurityUtils.getSubject().logout();

在方法前使用shiro注解实现权限校验，如：@RequiresPermissions(value = {"用户管理"}) 表示当前用户必须拥有用户管理的权限；

四、前端实现及效果展示
1、登录

源码：srcmainresourcestemplateslogin.ftl

用户名：admin

密码：1



 

 2、系统管理-菜单管理

菜单管理页面源码：srcmainresourcestemplatespowermenu.ftl

里面使用了ztree实现的菜单的新建、编辑、删除；

菜单管理的后台接口：com.zjt.web.MenuController.java



注意一级菜单在顶部显示，且一级菜单名不可为纯数字；

二级三级菜单在左侧显示，且最多只能到三级菜单；

 

 3、系统管理-角色管理

srcmainresourcestemplatespowerrole.ftl

com.zjt.web.RoleAdminController.java

页面使用了jqgrid表格插件；



并可以设置每个角色对应的菜单权限：



4、系统管理-用户管理

 srcmainresourcestemplatespoweruser.ftl

 com.zjt.web.UserAdminController.java

 

选择行后可以设置角色：



 

 五、后记
 本后台管理系统可作为通用的后台管理系统，她简单纯净；内置完善的菜单管理+角色管理+用户管理；拿来即用；

使用技术涉及：

springboot+springmvc+mysql+mybatis+通用mapper+分页插件+shiro+freemarker+layui+ztree

 其中layui模板使用的是layuicms2.0

 

本项目源码：

 https://github.com/zhaojiatao/springboot-zjt-chapter10-springboot-mysql-mybatis-shiro-freemarker-layui.git

 sql脚本含在项目sql文件夹中


转自：
https://www.erlo.vip/share/9/4206.html

