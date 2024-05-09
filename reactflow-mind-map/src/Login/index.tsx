import React, { useState } from 'react';
import axios from 'axios';
import "../index.css"

axios.defaults.withCredentials = true

const LoginPage: React.FC = () => {
    const [username, setUsername] = useState('');
    const [password, setPassword] = useState('');
    const [registerUsername, setRegisterUsername] = useState('');
    const [registerPassword, setRegisterPassword] = useState('');
    // const [error, setError] = useState('');
  
    const handleLogin = async (e: React.ChangeEvent<any>) => {
      e.preventDefault();
      try {
        console.log(username, password)
        const response = await axios.post("http://127.0.0.1:5000/login", {
            'username' : username,
            'password' : password
        }, { withCredentials: true });
        console.log(response.status); // Handle success response
        console.log(response.data);
        window.location.href = "/flow"
      } catch (error) {
            // setError('Invalid username or password');
            alert(error);
      }
    };
    
    const handleRegister = async (e: React.ChangeEvent<any>) => {
        e.preventDefault();
        try {
            console.log(registerUsername, registerPassword)
            const response = await axios.post("http://127.0.0.1:5000/users", {
            'username' : registerUsername,
            'password' : registerPassword
        }, { withCredentials: true });

        alert(response.status + " New user added")
        } catch (error) {
            alert(error)
        }

    }

    return (
    <div className='mainContainer'>
        <div className={'titleContainer'}>
            <div>Quest Tracker</div>
        </div>
        <div>
            A capstone project by Thomas Phan
        </div>
        <div className="semiTitleContainer"> 
            <div>Login</div>
        </div>
        <br />
        <form onSubmit={handleLogin}>
            <div className='inputContainer'>
                <input
                    className="input-margin"
                    type="text"
                    placeholder="Username"
                    value={username}
                    onChange={(e) => setUsername(e.target.value)}
                />
            </div>
            <div className='inputContainer'>
                <input
                    className="input-margin"
                    type="password"
                    placeholder="Password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                />
            </div>
            <button type="submit">Login</button>
        </form>
        <div className="semiTitleContainer"> 
            <div>Register</div>
        </div>
        <form onSubmit={handleRegister}>
        <div className='inputContainer'>
                <input
                    className="input-margin"
                    type="text"
                    placeholder="Username"
                    value={registerUsername}
                    onChange={(e) => setRegisterUsername(e.target.value)}
                />
            </div>
            <div className='inputContainer'>
                <input
                    className="input-margin"
                    type="password"
                    placeholder="Password"
                    value={registerPassword}
                    onChange={(e) => setRegisterPassword(e.target.value)}
                />
            </div>
            <button type="submit">Register</button>
        </form>
    </div>


    );
};
  
export default LoginPage;