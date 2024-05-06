import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom"
import LoginPage from "../Login/index"
import ErrorPage from  "../ErrorPage/index"
import { ReactFlowProvider } from "reactflow"
import Flow from "../App/index"

const Router = () => {
    return (
        <BrowserRouter>
            <Routes>
                <Route path="*" element={<ErrorPage />}/>
                <Route path="/" element={<LoginPage />}/>
                <Route path="/flow" element={<ReactFlowProvider><Flow /></ReactFlowProvider>}/>
            </Routes>
        </BrowserRouter>
    )
}

export default Router;