package org.javaboy.formlogin;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

/**
 * @作者 江南一点雨
 * @公众号 江南一点雨
 * @微信号 a_java_boy
 * @GitHub https://github.com/lenve
 * @博客 http://wangsong.blog.csdn.net
 * @网站 http://www.javaboy.org
 */
@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    @Bean
    PasswordEncoder passwordEncoder() {
        return NoOpPasswordEncoder.getInstance();
    }
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication()
                .withUser("javaboy")
                .password("123").roles("admin");
    }

    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring().antMatchers("/js/**", "/css/**","/images/**");
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .anyRequest().authenticated()
                .and()
                .formLogin()
                .loginPage("/login.html")   // 配置 登录页面
                .loginProcessingUrl("/doLogin") // 配置 登录用户密码请求的url
                .usernameParameter("name")  // default is username 配置 usernameParameter
                .passwordParameter("passwd") // default is password 配置 passwordParameter
                .defaultSuccessUrl("/index")  // 配置 登录成功后跳转的url, 会重定向到登录之前的访问的url
//                .successForwardUrl("/index") // 配置 登录成功后跳转的url, 只需要配置一个即可
                .failureForwardUrl("/f2")              // 配置 登录失败后跳转的url, 登录失败之后会发生服务端跳转,只需要配置一个即可,
//                .failureUrl("/f1")  // 配置 登录失败后跳转的url, 登录失败后 发生重定向
                .permitAll()
                .and()
                .logout()
//                .logoutUrl("/logout")
//                .logoutRequestMatcher(new AntPathRequestMatcher("/logout","POST"))
                .logoutSuccessUrl("/index")   // 配置 登出成功后跳转的页面
                .deleteCookies()  // 配置 登出成功后删除的cookie
                .clearAuthentication(true) // 配置 登出成功后清除认证信息
                .invalidateHttpSession(true) // 配置 登出成功后清除session
                .permitAll()  // 配置 登出页面不需要认证
                .and()
                .csrf().disable();
    }
}
