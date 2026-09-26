import { logger } from '@altipla/logging'
import { CloudTasksClient } from '@google-cloud/tasks'
import ksuid from 'ksuid'
import { OAuth2Client } from 'google-auth-library'

export type QueueName = string & { readonly _: unique symbol }
export function queueName(name: string): QueueName {
  return name as QueueName
}

const ENV_PRODUCTION = process.env.NODE_ENV === 'production'

export type CloudTasksConfig = {
  /** JSON credentials for the service account. */
  credentials?: string

  /** Google Cloud project ID. */
  project: string

  /** Location of the queue. Example: `us-central1` or `europe-west1`	. */
  location: string

  /** Audience of the token for the OIDC authentication. Most of the time it will be the URL of the service. */
  audience: string

  /** The service account email to use for the OIDC authentication. */
  serviceAccount: string

  /** Base URL of the service to concatenate with the URL of the task. */
  baseURL: string

  /** Force the environment to be production or development. By default it will be the value of the NODE_ENV environment variable. */
  forcedEnvironment?: 'production' | 'development'
}
export function defineTasksConfig(config: CloudTasksConfig): CloudTasksConfig {
  return config
}

let cachedTasksClient: CloudTasksClient
function initTasksClient(config: CloudTasksConfig) {
  if (!cachedTasksClient) {
    cachedTasksClient = new CloudTasksClient({
      credentials: config.credentials ? JSON.parse(config.credentials) : undefined,
    })
  }
  return cachedTasksClient
}

/**
 * Send a task to a queue.
 * @param config - Configuration of the library.
 * @param queue - Name of the queue to send the task to.
 * @param url - Target URL of the task to send.
 * @param payload - Payload of the task to send.
 * @returns Generated name of the task.
 */
export async function sendTask(config: CloudTasksConfig, queue: QueueName, url: string, payload: string) {
  const tasksClient = initTasksClient(config)

  let u = new URL(url, config.baseURL)

  if (!ENV_PRODUCTION && config.forcedEnvironment !== 'production') {
    logger.debug({
      msg: 'simulate local task',
      url: u.toString(),
      payload,
    })
    void fetch(u.toString(), {
      method: 'POST',
      body: payload,
      headers: {
        'x-cloudtasks-queuename': queue,
        'x-cloudtasks-taskname': ksuid.randomSync().string,
        'x-cloudtasks-taskretrycount': '0',
        authorization: `Bearer local-token`,
      },
    })
    return ksuid.randomSync().string
  }

  const [response] = await tasksClient.createTask({
    parent: tasksClient.queuePath(config.project, config.location, queue),
    task: {
      httpRequest: {
        httpMethod: 'POST',
        url: u.toString(),
        body: Buffer.from(payload).toString('base64'),
        oidcToken: {
          audience: config.audience,
          serviceAccountEmail: config.serviceAccount,
        },
      },
    },
  })
  return response.name
}

export type Task = {
  queueName: QueueName
  taskName: string
  retryCount: number
}
const authClient = new OAuth2Client()

export function handleCallback(
  config: CloudTasksConfig,
  callback: (request: Request, task: Task) => Response | Promise<Response>,
): (request: Request) => Promise<Response> {
  return async function (request) {
    let authorization = request.headers.get('authorization')
    if (!authorization?.startsWith('Bearer ')) {
      return new Response('invalid authorization', { status: 401 })
    }
    let bearer = authorization.slice(7)

    if (!ENV_PRODUCTION && config.forcedEnvironment !== 'production') {
      if (bearer !== 'local-token') {
        return new Response('invalid authentication', { status: 401 })
      }
    } else {
      try {
        await authClient.verifyIdToken({
          idToken: bearer,
          audience: config.audience,
        })
      } catch {
        return new Response('invalid authentication', { status: 401 })
      }
    }

    return callback(request, readTask(request.headers))
  }
}

export function handleAstroCallback<Context extends { request: Request }>(
  config: CloudTasksConfig,
  callback: (context: Context, task: Task) => Response | Promise<Response>,
): (context: Context) => Promise<Response> {
  return function (context) {
    const handler = handleCallback(config, function (request, task) {
      return callback(context, task)
    })
    return handler(context.request)
  }
}

function readTask(headers: Headers): Task {
  return {
    queueName: headers.get('x-cloudtasks-queuename') as QueueName,
    taskName: headers.get('x-cloudtasks-taskname')!,
    retryCount: parseInt(headers.get('x-cloudtasks-taskretrycount')!, 10),
  } satisfies Task
}
