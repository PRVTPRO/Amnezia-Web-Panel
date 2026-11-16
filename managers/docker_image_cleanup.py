"""Keep the image store from filling up with dangling images.

Every protocol installer tags its build with a fixed name
(``docker build --no-cache --pull -t <name> <dir>``). Docker does not delete
the previously built image when the tag moves, so the old layers stay behind
as ``<none>:<none>``. A reinstall therefore costs one more dangling image each
time, and ``docker rmi <name>`` on uninstall only drops the current tag.

The helpers below record the image ID before a rebuild and drop exactly that
image afterwards. Nothing here is fatal: a leftover image is not worth a failed
install, so every command is best-effort and logs instead of raising.
"""

import logging

logger = logging.getLogger(__name__)

_IMAGE_ID_FMT = "docker image inspect -f '{{.Id}}' %s"


def image_id(ssh, tag):
    """Current image ID behind ``tag``, or None when the tag does not exist."""
    try:
        out, _err, code = ssh.run_sudo_command(_IMAGE_ID_FMT % tag)
    except Exception as exc:  # transport hiccup must not break the install
        logger.warning("image_id(%s): %s", tag, exc)
        return None
    if code != 0:
        return None
    value = (out or '').strip()
    return value or None


def image_in_use(ssh, image_id_):
    """True when any container (running or stopped) still uses this image."""
    try:
        out, _err, code = ssh.run_sudo_command(
            'docker ps -aq --filter ancestor=%s' % image_id_)
    except Exception as exc:
        logger.warning("image_in_use(%s): %s", image_id_, exc)
        return True
    if code != 0:
        # Unknown state: keeping an image is always safe, deleting a used one
        # breaks a container.
        return True
    return bool((out or '').strip())


def drop_replaced_image(ssh, tag, old_image_id):
    """Delete the image that a just-finished rebuild replaced.

    Returns True when an image was actually removed. Skips silently when
    there was no previous image, when the rebuild produced the same ID, or
    when a container still uses the old image.
    """
    if not old_image_id:
        return False
    current = image_id(ssh, tag)
    if current and current == old_image_id:
        # Build reused the existing image (identical content); the tag still
        # points at it, so there is nothing dangling.
        return False
    if image_in_use(ssh, old_image_id):
        logger.info("kept replaced image %s of %s: still used by a container",
                    old_image_id, tag)
        return False
    try:
        out, err, code = ssh.run_sudo_command('docker rmi %s' % old_image_id)
    except Exception as exc:
        logger.warning("docker rmi %s: %s", old_image_id, exc)
        return False
    if code != 0:
        logger.warning("could not remove replaced image %s of %s: %s",
                       old_image_id, tag, ((err or out) or '').strip()[:200])
        return False
    logger.info("removed replaced image %s of %s", old_image_id, tag)
    return True
