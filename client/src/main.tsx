import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { MantineProvider, createTheme } from '@mantine/core';
import { Notifications } from '@mantine/notifications';
import '@mantine/core/styles.css';
import '@mantine/code-highlight/styles.css';
import '@mantine/notifications/styles.css';
import './App.css';
import App from './App.tsx';

const theme = createTheme({
  colors: {
    forest: [
      '#DAF1DE',
      '#8EB69B',
      '#5a8f7a',
      '#235347',
      '#163832',
      '#0B2B26',
      '#051F20',
      '#051F20',
      '#051F20',
      '#051F20',
    ],
  },
  primaryColor: 'forest',
  primaryShade: 3,
  defaultRadius: 'md',
});

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <MantineProvider theme={theme} defaultColorScheme="dark">
      <Notifications position="bottom-center" />
      <App />
    </MantineProvider>
  </StrictMode>,
);
