from typing import Optional


class CSP:
    base_uri: set[str]
    child_src: set[str]
    connect_src: set[str]
    default_src: set[str]
    font_src: set[str]
    form_action: set[str]
    frame_ancestors: set[str]
    frame_src: set[str]
    img_src: set[str]
    manifest_src: set[str]
    media_src: set[str]
    object_src: set[str]
    report_sample: set[str]
    report_to: set[str]
    sandbox: set[str]
    script_src: set[str]
    script_src_attr: set[str]
    script_src_elem: set[str]
    strict_dynamic: set[str]
    style_src: set[str]
    style_src_attr: set[str]
    style_src_elem: set[str]
    unsafe_hashes: set[str]
    upgrade_insecure_requests: set[str]
    worker_src: set[str]

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
