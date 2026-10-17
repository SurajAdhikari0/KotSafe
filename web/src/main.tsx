import React from 'react';
import ReactDOM from 'react-dom/client';
import App from './App.tsx';
import { DesktopApp } from './desktop/DesktopApp.tsx';

const rootElement = document.getElementById('root');
if (rootElement) {
  const desktopMode =
    import.meta.env.VITE_KOTSAFE_DESKTOP === 'true' ||
    new URLSearchParams(window.location.search).has('desktop');

  ReactDOM.createRoot(rootElement).render(
    <React.StrictMode>
      {desktopMode ? <DesktopApp /> : <App />}
    </React.StrictMode>
  );
}
