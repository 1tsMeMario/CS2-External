#include "sdk.hpp"

using namespace KeyAuth;

std::string name = xorstr_("Athena Development");
std::string ownerid = xorstr_("");
std::string version = xorstr_("1.0");
std::string url = xorstr_("https://keyauth.win/api/1.3/");
std::string path = xorstr_("");

api KeyAuthApp(name, ownerid, version, url, path);

#define build_version 14073

enum class login_status
{
    LOGGED_IN,
    REGISTER,
    LOGIN
};

login_status status = login_status::LOGIN;

void background()
{
	while (!overlay.gui.quit)
	{

		std::this_thread::sleep_for(std::chrono::milliseconds(1));
	}
	return;
}

void sessionStatus() {
    KeyAuthApp.check(true);
    if (!KeyAuthApp.response.success) {
        exit(0);
    }

    if (KeyAuthApp.response.isPaid) {
        while (true) {
            std::this_thread::sleep_for(std::chrono::milliseconds(20000));
            KeyAuthApp.check();
            if (!KeyAuthApp.response.success) {
                exit(0);
            }
        }
    }
}

void checkAuthenticated() {
    while (true) {
        if (GlobalFindAtomA(ownerid.c_str()) == 0) {
            exit(13);
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(1000));
    }
}

void init_process()
{
    if (!SDK.initialized)
    {
        if (SDK.UpdateOffsets(false) == false)
        {
            logger.error(xorstr_("Failed to auto update offsets."));
        }

        SDK.process = std::make_shared<pProcess>();
        if (!SDK.process->AttachProcessHj(xorstr_("cs2.exe"), false))
        {
            logger.error(xorstr_("Failed to attach to process"));
        }

        logger.info(xorstr_("Attached to process"));

        SDK.GetClientBase();
        SDK.GetEngineBase();

        logger.info(xorstr_("Found cs2 modules"));

        int game_version = SDK.process->read<int>(SDK.engine_dll.base + offsets.dwBuildNumber);

        if (game_version < build_version)
        {
            logger.error((xorstr_("Unsupported Version -> CS2 Build ") + std::to_string(game_version)).c_str());
        }
        else if (game_version > build_version)
        {
            logger.warning((xorstr_("You are running a newer build. -> CS2 Build ") + std::to_string(game_version)).c_str());
            if (!logger.ask(xorstr_("Proceed? (Y/n) ")))
            {
                overlay.gui.quit = true;
            }
        }

        logger.info(xorstr_("SDK initialized"));
        logger.close_console();
        SDK.initialized = true;
    }
}

void overlay_menu(std::string overlay_name)
{
    init_process();
    overlay.gui.set_next_window(0.5);
    ImGui::Begin(overlay_name.c_str(), NULL, ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoTitleBar);
    std::string title = xorstr_("External Overlay -> FPS: ");
    title += std::to_string((int)overlay.get_fps());
    overlay.gui.center_text(title.c_str());
    overlay.gui.spacer();
    ImGui::Separator();
    overlay.gui.center_text(xorstr_("Settings"));
    ImGui::Checkbox(xorstr_("Streamproof"), &overlay.gui.streamproof);
    overlay.gui.tooltip(xorstr_("Prevents the overlay from being captured by the anticheats. (Recommended)"));
    ImGui::Checkbox(xorstr_("Vsync"), &overlay.gui.vsync);
    overlay.gui.tooltip(xorstr_("Synchronize the overlay framerate to the monitor's refresh rate."));
    ImGui::End();
}

void overlay_login(std::string overlay_name)
{
    overlay.gui.set_next_window(0.1);
    ImGui::Begin(overlay_name.c_str(), nullptr, ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoTitleBar);

    overlay.gui.center_text(xorstr_("Athena Development"));
    overlay.gui.spacer();

    static char username[64] = "";
    static char password[64] = "";

    overlay.gui.center_input_text(xorstr_("Username:"), xorstr_("##username"), username, IM_ARRAYSIZE(username), ImGuiInputTextFlags_CharsNoBlank);
    overlay.gui.center_input_text(xorstr_("Password:"), xorstr_("##password"), password, IM_ARRAYSIZE(password), ImGuiInputTextFlags_Password);

    overlay.gui.spacer();
    ImGui::SetCursorPosX((ImGui::GetWindowWidth() - ImGui::CalcTextSize(xorstr_("Login")).x - ImGui::GetStyle().ItemSpacing.x - ImGui::CalcTextSize(xorstr_("Register")).x) * 0.5f);

    if (ImGui::Button(xorstr_("Login")))
    {

        KeyAuthApp.login(username, password);
        if (!KeyAuthApp.response.success)
        {
            logger.error(xorstr_("Username or Password Invalid."));
        }
        else
        {
            overlay.start_background_thread(sessionStatus);
            overlay.start_background_thread(checkAuthenticated);
            status = login_status::LOGGED_IN;
        }
    }

    ImGui::SameLine();
    if (ImGui::Button(xorstr_("Register")))
    {
        status = login_status::REGISTER;
    }

    ImGui::End();
}

void overlay_register(std::string overlay_name)
{
    overlay.gui.set_next_window(0.13);
    ImGui::Begin(overlay_name.c_str(), nullptr, ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoTitleBar);

    overlay.gui.center_text(xorstr_("Register Account"));
    overlay.gui.spacer();

    static char username[64] = "";
    static char password[64] = "";
    static char license[64] = "";

    overlay.gui.center_input_text(xorstr_("Username:"), xorstr_("##reg_username"), username, IM_ARRAYSIZE(username), ImGuiInputTextFlags_CharsNoBlank);
    overlay.gui.center_input_text(xorstr_("Password:"), xorstr_("##reg_password"), password, IM_ARRAYSIZE(password), ImGuiInputTextFlags_Password);
    overlay.gui.center_input_text(xorstr_("License:"), xorstr_("##reg_license"), license, IM_ARRAYSIZE(license), ImGuiInputTextFlags_CharsNoBlank);

    overlay.gui.spacer();
    ImGui::SetCursorPosX((ImGui::GetWindowWidth() - ImGui::CalcTextSize(xorstr_("Submit")).x - ImGui::GetStyle().ItemSpacing.x - ImGui::CalcTextSize(xorstr_("Back")).x) * 0.5f);

    if (ImGui::Button((xorstr_("Submit"))))
    {
        KeyAuthApp.regstr(username, password, license);
        if (!KeyAuthApp.response.success)
        {
            logger.error(xorstr_("Failed to register an account."));
        }
        else
        {
            status = login_status::LOGIN;
        }
    }

    ImGui::SameLine();
    if (ImGui::Button(xorstr_("Back")))
    {
        status = login_status::LOGIN;
    }

    ImGui::End();
}

DWORD MainThread()
{
    logger.create_console();
    system(xorstr_("cls"));
    if (!librarys::init())
    {
        logger.error(("Failed to initialize core dependencies"));
    }

	logger.info(xorstr_("Waiting for game"));

	overlay.wait_for_game_load();
	overlay.create_overlay();
	protections.RenameFile();
    KeyAuthApp.init();
    if (!KeyAuthApp.response.success)
    {
        logger.error(xorstr_("Couldn't connect to server."));
    }

    if (KeyAuthApp.checkblack())
    {
        logger.error(xorstr_("Account Disabled. Please Contact Athena Development @ discord.gg/athenadev."));
    }
	overlay.setup_imgui();

    logger.info(xorstr_("Initialization complete"));

    SetForegroundWindow(overlay.gui.athena_overlay);
	overlay.start_background_thread(background);
	while (!overlay.gui.quit)
	{
		overlay.start_render();
		if (overlay.gui.showmenu)
		{
            switch (status)
            {
                case login_status::LOGGED_IN:
                    overlay_menu(xorstr_("##athena_menu"));
                    break;
                case login_status::LOGIN:
                    overlay_login(xorstr_("##athena_login"));
                    break;
                case login_status::REGISTER:
                    overlay_register(xorstr_("##athena_register"));
                    break;
            }
		}
        overlay.show_watermark(xorstr_("Athena Development v1.0"), 255, 255, 255, 255);
		overlay.end_render();
	}
    logger.info(("Shutting down..."));
	overlay.shutdown();
    SDK.process->Close();
	Sleep(3000);
	exit(0);
}

int APIENTRY WinMain(HINSTANCE hInstance,
    HINSTANCE hPrevInstance,
    LPSTR     lpCmdLine,
    int       nCmdShow)
{
	MainThread();
}