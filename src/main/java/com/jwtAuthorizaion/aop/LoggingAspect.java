package com.jwtAuthorizaion.aop;

import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.Arrays;

@Aspect
@Component
public class LoggingAspect {

    private static final Logger log =
            LoggerFactory.getLogger(LoggingAspect.class);

    // 🔹 Controller logging
    @Around("execution(* com.jwtAuthorizaion.controller..*(..))")
    public Object logController(ProceedingJoinPoint joinPoint) throws Throwable {

        log.info("Controller: {} | Args: {}",
                joinPoint.getSignature().toShortString(),
                maskSensitiveData(joinPoint.getArgs()));

        Object result = joinPoint.proceed();

        log.info("⬅  Controller Response: {} | Result: {}",
                joinPoint.getSignature().toShortString(),
                result);

        return result;
    }

    // 🔹 Service logging with execution time
    @Around("execution(* com.jwtAuthorizaion.service..*(..))")
    public Object logService(ProceedingJoinPoint joinPoint) throws Throwable {

        long start = System.currentTimeMillis();

        try {
            Object result = joinPoint.proceed();

            long timeTaken = System.currentTimeMillis() - start;

            log.info(" Service: {} | Time: {} ms",
                    joinPoint.getSignature().toShortString(),
                    timeTaken);

            return result;

        } catch (Exception ex) {

            log.error(" Exception in: {} | Message: {}",
                    joinPoint.getSignature().toShortString(),
                    ex.getMessage());

            throw ex;
        }
    }

    // 🔐 Mask sensitive values (passwords, tokens)
    private Object[] maskSensitiveData(Object[] args) {
        return Arrays.stream(args)
                .map(arg -> {
                    if (arg != null && arg.toString().toLowerCase().contains("password")) {
                        return "******";
                    }
                    return arg;
                })
                .toArray();
    }
}
