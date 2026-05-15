import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import App from "./App.jsx";

describe("App", () => {
  it("renders the hero and default classic tab", () => {
    render(<App />);

    expect(screen.getByText("Playground educatif")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Classic" })).toBeInTheDocument();
    expect(screen.getByText("Outils d'analyse")).toBeInTheDocument();
  });

  it("switches tabs and updates the hero card", async () => {
    const user = userEvent.setup();
    render(<App />);

    await user.click(screen.getByRole("button", { name: "Hash" }));

    expect(screen.getByRole("heading", { name: "Hash" })).toBeInTheDocument();
    expect(screen.getByText("HMAC-SHA256")).toBeInTheDocument();
  });
});
