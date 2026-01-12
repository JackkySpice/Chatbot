.class public final Landroidx/appcompat/view/menu/qp0;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static b:Landroidx/appcompat/view/menu/qp0;

.field public static final c:Landroidx/appcompat/view/menu/rp0;


# instance fields
.field public a:Landroidx/appcompat/view/menu/rp0;


# direct methods
.method static constructor <clinit>()V
    .locals 7

    new-instance v6, Landroidx/appcompat/view/menu/rp0;

    const/4 v1, 0x0

    const/4 v2, 0x0

    const/4 v3, 0x0

    const/4 v4, 0x0

    const/4 v5, 0x0

    move-object v0, v6

    invoke-direct/range {v0 .. v5}, Landroidx/appcompat/view/menu/rp0;-><init>(IZZII)V

    sput-object v6, Landroidx/appcompat/view/menu/qp0;->c:Landroidx/appcompat/view/menu/rp0;

    return-void
.end method

.method public constructor <init>()V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public static declared-synchronized b()Landroidx/appcompat/view/menu/qp0;
    .locals 2

    const-class v0, Landroidx/appcompat/view/menu/qp0;

    monitor-enter v0

    :try_start_0
    sget-object v1, Landroidx/appcompat/view/menu/qp0;->b:Landroidx/appcompat/view/menu/qp0;

    if-nez v1, :cond_0

    new-instance v1, Landroidx/appcompat/view/menu/qp0;

    invoke-direct {v1}, Landroidx/appcompat/view/menu/qp0;-><init>()V

    sput-object v1, Landroidx/appcompat/view/menu/qp0;->b:Landroidx/appcompat/view/menu/qp0;

    goto :goto_0

    :catchall_0
    move-exception v1

    goto :goto_1

    :cond_0
    :goto_0
    sget-object v1, Landroidx/appcompat/view/menu/qp0;->b:Landroidx/appcompat/view/menu/qp0;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    monitor-exit v0

    return-object v1

    :goto_1
    monitor-exit v0

    throw v1
.end method


# virtual methods
.method public a()Landroidx/appcompat/view/menu/rp0;
    .locals 1

    iget-object v0, p0, Landroidx/appcompat/view/menu/qp0;->a:Landroidx/appcompat/view/menu/rp0;

    return-object v0
.end method

.method public final declared-synchronized c(Landroidx/appcompat/view/menu/rp0;)V
    .locals 2

    monitor-enter p0

    if-nez p1, :cond_0

    :try_start_0
    sget-object p1, Landroidx/appcompat/view/menu/qp0;->c:Landroidx/appcompat/view/menu/rp0;

    iput-object p1, p0, Landroidx/appcompat/view/menu/qp0;->a:Landroidx/appcompat/view/menu/rp0;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    monitor-exit p0

    return-void

    :catchall_0
    move-exception p1

    goto :goto_1

    :cond_0
    :try_start_1
    iget-object v0, p0, Landroidx/appcompat/view/menu/qp0;->a:Landroidx/appcompat/view/menu/rp0;

    if-eqz v0, :cond_2

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/rp0;->n()I

    move-result v0

    invoke-virtual {p1}, Landroidx/appcompat/view/menu/rp0;->n()I

    move-result v1
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    if-ge v0, v1, :cond_1

    goto :goto_0

    :cond_1
    monitor-exit p0

    return-void

    :cond_2
    :goto_0
    :try_start_2
    iput-object p1, p0, Landroidx/appcompat/view/menu/qp0;->a:Landroidx/appcompat/view/menu/rp0;
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    monitor-exit p0

    return-void

    :goto_1
    monitor-exit p0

    throw p1
.end method
