- **The open mode is an app with no auth service, and the code now says so.** `AuthService.enabled`
  is removed. It always returned true, and the API and web console guards that read it now ask only
  whether a service is attached. A removed settings key built in code, such as
  `SecuritySettings(require_sign_in=False)`, is now refused with the same message the loader gives,
  rather than dropped. `GET /security/posture` names the `allow_no_auth` open mode as a loosening
  when an app runs with no service. The web console seam digest moves. (`vault BACKLOG #3062`)
