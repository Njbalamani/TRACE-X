import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { BrowserRouter, Route, Routes } from "react-router-dom";
import "./index.css";
import Layout from "./components/Layout";
import Dashboard from "./pages/Dashboard";
import Investigations from "./pages/Investigations";
import CaseDetail from "./pages/CaseDetail";
import { GlobalEvidence, GlobalFindings, GlobalIntegrity, GlobalReports, Settings } from "./pages/GlobalPages";
import { Navigate } from "react-router-dom";

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <BrowserRouter>
      <Layout>
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/investigations" element={<Investigations />} />
          <Route path="/cases/:id/:tab" element={<CaseDetail />} />
          <Route path="/cases/:id" element={<Navigate to="overview" replace />} />
          <Route path="/evidence" element={<GlobalEvidence />} />
          <Route path="/findings" element={<GlobalFindings />} />
          <Route path="/integrity" element={<GlobalIntegrity />} />
          <Route path="/reports" element={<GlobalReports />} />
          <Route path="/settings" element={<Settings />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </Layout>
    </BrowserRouter>
  </StrictMode>,
);
