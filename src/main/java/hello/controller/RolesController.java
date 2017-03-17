package hello.controller;

import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiResponse;
import io.swagger.annotations.ApiResponses;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.stream.Collectors;

@RestController
public class RolesController {
    @ApiOperation(value = "Returns user roles", notes = "Returns the roles for the user.", response = String.class)
    @ApiResponses(value = {
            @ApiResponse(code = 200, message = "Successful retrieval of user detail", response = String.class),
            @ApiResponse(code = 404, message = "User with given username does not exist")}
    )
    @Secured("ROLE_ADMIN")
    @RequestMapping("/roles")
    public String greeting(@RequestParam(value = "name", defaultValue = "fubar") String name)
            throws RuntimeException {
        UserDetails userDetails =
                (UserDetails) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        if (userDetails != null && userDetails.getUsername().equals(name)) {
            return userDetails.getAuthorities().stream().map(item -> item.getAuthority())
                    .collect(Collectors.toList())
                    .toString();
        }
        return name;
    }
}
