.class public Landroidx/appcompat/view/menu/mz1;
.super Ljava/lang/Object;
.source "SourceFile"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Landroidx/appcompat/view/menu/mz1$a;
    }
.end annotation


# static fields
.field public static volatile b:Landroidx/appcompat/view/menu/mz1;

.field public static final c:Landroidx/appcompat/view/menu/mz1;


# instance fields
.field public final a:Ljava/util/Map;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    new-instance v0, Landroidx/appcompat/view/menu/mz1;

    const/4 v1, 0x1

    invoke-direct {v0, v1}, Landroidx/appcompat/view/menu/mz1;-><init>(Z)V

    sput-object v0, Landroidx/appcompat/view/menu/mz1;->c:Landroidx/appcompat/view/menu/mz1;

    return-void
.end method

.method public constructor <init>(Z)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    invoke-static {}, Ljava/util/Collections;->emptyMap()Ljava/util/Map;

    move-result-object p1

    iput-object p1, p0, Landroidx/appcompat/view/menu/mz1;->a:Ljava/util/Map;

    return-void
.end method

.method public static a()Landroidx/appcompat/view/menu/mz1;
    .locals 2

    sget-object v0, Landroidx/appcompat/view/menu/mz1;->b:Landroidx/appcompat/view/menu/mz1;

    if-eqz v0, :cond_0

    return-object v0

    :cond_0
    const-class v0, Landroidx/appcompat/view/menu/mz1;

    monitor-enter v0

    :try_start_0
    sget-object v1, Landroidx/appcompat/view/menu/mz1;->b:Landroidx/appcompat/view/menu/mz1;

    if-eqz v1, :cond_1

    monitor-exit v0

    return-object v1

    :catchall_0
    move-exception v1

    goto :goto_0

    :cond_1
    const-class v1, Landroidx/appcompat/view/menu/mz1;

    invoke-static {v1}, Landroidx/appcompat/view/menu/k02;->a(Ljava/lang/Class;)Landroidx/appcompat/view/menu/mz1;

    move-result-object v1

    sput-object v1, Landroidx/appcompat/view/menu/mz1;->b:Landroidx/appcompat/view/menu/mz1;

    monitor-exit v0

    return-object v1

    :goto_0
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    throw v1
.end method


# virtual methods
.method public final b(Landroidx/appcompat/view/menu/s32;I)Landroidx/appcompat/view/menu/m02$d;
    .locals 2

    iget-object v0, p0, Landroidx/appcompat/view/menu/mz1;->a:Ljava/util/Map;

    new-instance v1, Landroidx/appcompat/view/menu/mz1$a;

    invoke-direct {v1, p1, p2}, Landroidx/appcompat/view/menu/mz1$a;-><init>(Ljava/lang/Object;I)V

    invoke-interface {v0, v1}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    invoke-static {p1}, Landroidx/appcompat/view/menu/fy0;->a(Ljava/lang/Object;)V

    const/4 p1, 0x0

    return-object p1
.end method
