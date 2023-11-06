from typing import Optional


class CSP:
    base_uri: list[str]
    child_src: list[str]
    connect_src: list[str]
    default_src: list[str]
    font_src: list[str]
    form_action: list[str]
    frame_ancestors: list[str]
    frame_src: list[str]
    img_src: list[str]
    manifest_src: list[str]
    media_src: list[str]
    object_src: list[str]
    report_sample: list[str]
    report_to: list[str]
    sandbox: list[str]
    script_src: list[str]
    script_src_attr: list[str]
    script_src_elem: list[str]
    strict_dynamic: list[str]
    style_src: list[str]
    style_src_attr: list[str]
    style_src_elem: list[str]
    unsafe_hashes: list[str]
    upgrade_insecure_requests: list[str]
    worker_src: list[str]

    def __init__(self, policy: Optional[str] = None):
        """
        Initialize a CSP object from a Content Security Policy string.
        """
        if not policy:
            return
        policy = policy.strip().removesuffix(";")
        policy_dict = {
            p.split()[0].replace("-", "_"): p.split()[1:] for p in policy.split(";")
        }
        for key in policy_dict.keys():
            if key not in self.__annotations__.keys():
                raise ValueError(
                    f'"{key.replace("_", "-")}" is not a valid CSP directive'
                )
        self.__dict__ = policy_dict

    def generate(self) -> str:
        """
        Generate a Content Security Policy string.
        """
        policy = "; ".join(
            [f'{k.replace("_", "-")} {(" ").join(v)}' for k, v in self.__dict__.items()]
        ).strip()
        policy += ";"
        return policy
