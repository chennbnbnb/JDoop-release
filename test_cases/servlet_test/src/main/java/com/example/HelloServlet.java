package com.example;

import jakarta.servlet.ServletException; 

import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.*;

// WebServlet注解表示这是一个Servlet，并映射到地址/:
@WebServlet(urlPatterns = "/")
public class HelloServlet extends HttpServlet {
    private static final long serialVersionUID = 1L;
	
	@Override
	public void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		doPost(request, response);
	}

	@Override
	public void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		// some code
        String t = request.getParameter("123");
		
        String[] args = {"echo", t};
        
		Runtime r = Runtime.getRuntime();

		try {
			Process p = r.exec(args, null, null);
			System.out.println(p.toString());
		} catch (IOException e) {
			;
		}
	}
}