import React from "react";
import { NavigationContainer } from "@react-navigation/native";
import { createNativeStackNavigator } from "@react-navigation/native-stack";
import HomeScreen from "./screens/HomeScreen";
import ProtectedScreen from "./screens/ProtectedScreen";
import ApiDemoScreen from "./screens/ApiDemoScreen";

export type RootStackParamList = {
  Home: undefined;
  Protected: undefined;
  ApiDemo: undefined;
};

const Stack = createNativeStackNavigator<RootStackParamList>();

function AppNavigator() {
  return (
    <NavigationContainer>
      <Stack.Navigator
        initialRouteName="Home"
        screenOptions={{
          headerStyle: {
            backgroundColor: "#646cff",
          },
          headerTintColor: "#fff",
          headerTitleStyle: {
            fontWeight: "bold",
          },
        }}
      >
        <Stack.Screen
          name="Home"
          component={HomeScreen}
          options={{ title: "Guardhouse RN Example" }}
        />
        <Stack.Screen
          name="Protected"
          component={ProtectedScreen}
          options={{ title: "Authorized Page" }}
        />
        <Stack.Screen
          name="ApiDemo"
          component={ApiDemoScreen}
          options={{ title: "API Demo" }}
        />
      </Stack.Navigator>
    </NavigationContainer>
  );
}

export default AppNavigator;
