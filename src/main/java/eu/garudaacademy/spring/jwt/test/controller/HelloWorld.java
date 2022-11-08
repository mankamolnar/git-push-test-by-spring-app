package eu.garudaacademy.spring.jwt.test.controller;

import eu.garudaacademy.spring.jwt.test.models.AuthenticationRequest;
import eu.garudaacademy.spring.jwt.test.models.AuthenticationResponse;
import eu.garudaacademy.spring.jwt.test.util.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.bind.annotation.*;

@RestController
public class HelloWorld {

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private UserDetailsService userDetailsService;

    @Autowired
    private JwtUtil jwtUtil;

    @RequestMapping({ "/hello" })
    public String hello() {
        return "Hello World";
    }

    /**
     * TOKEN GENERALASHOZ // BELEPESHEZ SZUKSEGES API
     */
    @RequestMapping(value = "/authenticate", method = RequestMethod.POST)
    public ResponseEntity<?> createAuthenticationToken(@RequestBody AuthenticationRequest authenticationRequest) {
        // AUTHENTIKÁLJUK A USERT
        // HIBAS CREDENTAILS ESETEN BadCredentailsException
        // HA A KOVETKEZO SOR LEMEGY SIKERESEN AKKOR TUDJUK HOGY AUTHENTIKALVA VAGYUNK
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        authenticationRequest.getUsername(), authenticationRequest.getPassword()));

        // BETOLTJUK A BEAUTHENTIKALT USER A DB-BŐL.
        final UserDetails userDetails
                = userDetailsService.loadUserByUsername(authenticationRequest.getUsername());

        // UTIL SEGITSEGEVEL LEGENERALJUK A TOKENT
        final String jwt = jwtUtil.generateToken(userDetails);

        // TOKEN-T A RESPONSE-BAN VISSZAADJUK
        return ResponseEntity.ok(new AuthenticationResponse(jwt));
    }
}
