package eu.garudaacademy.spring.jwt.test.filter;

import eu.garudaacademy.spring.jwt.test.config.MyUserDetailsService;
import eu.garudaacademy.spring.jwt.test.util.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * - Filterek egy request szerverre való beérkezése előtt/után tudnak lefutni!
 */
@Component
public class JwtRequestFilter extends OncePerRequestFilter {

    @Autowired
    private MyUserDetailsService userDetailsService;

    @Autowired
    private JwtUtil jwtUtil;

    /**
     * - Itt történik a request feldolgozása!
     * - UsernamePasswordAuthenticationToken -> olyasmi mint usereknél a UserDetails volt, tehát egy a Spring-ben
     *   definialt objektum amit az autentikaciohoz hasznal. Tartalmazza a felhasznalo objektumot (principal),
     *   [credentialoket], es a felhasznalo jogkoreit, illetve beallithato neki hogy milyen IP alol erkezett a keres,
     *   es hogy milyen sessionID tartozik a klienshez.
     * - WebAuthenticationDetailsSource -> o az objektum ami tartalmazza az IP-t es a session ID-t.
     *
     */
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        final String authHeader = request.getHeader("Authorization");

        String jwt = null;
        String username = null;

        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            jwt = authHeader.substring(7);
            username = jwtUtil.extractUsername(jwt);
        }

        // VAN FELHASZNALONEV ES NEM VAGYUNK BEJELENTKEZVEKM,
        if (username != null &&  SecurityContextHolder.getContext().getAuthentication() == null) {
            UserDetails user = this.userDetailsService.loadUserByUsername(username);

            if (jwtUtil.validateToken(jwt, user)) {
                // HA VALID A TOKEN BE KELL JELENTKEZTETNI SPRINGBE, EZ TORTENIK A TOKENNEL.
                UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(
                        user, null, user.getAuthorities());

                token.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                SecurityContextHolder.getContext().setAuthentication(token);
            }
        }

        filterChain.doFilter(request, response);
    }
}
