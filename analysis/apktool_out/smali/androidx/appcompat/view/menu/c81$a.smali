.class public final Landroidx/appcompat/view/menu/c81$a;
.super Ljava/lang/Object;
.source "SourceFile"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Landroidx/appcompat/view/menu/c81;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "a"
.end annotation


# static fields
.field public static final synthetic a:Landroidx/appcompat/view/menu/c81$a;

.field public static final b:Z

.field public static final c:Ljava/lang/String;

.field public static final d:Landroidx/appcompat/view/menu/f80;

.field public static e:Landroidx/appcompat/view/menu/e81;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    new-instance v0, Landroidx/appcompat/view/menu/c81$a;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/c81$a;-><init>()V

    sput-object v0, Landroidx/appcompat/view/menu/c81$a;->a:Landroidx/appcompat/view/menu/c81$a;

    const-class v0, Landroidx/appcompat/view/menu/c81;

    invoke-static {v0}, Landroidx/appcompat/view/menu/zn0;->b(Ljava/lang/Class;)Landroidx/appcompat/view/menu/h70;

    move-result-object v0

    invoke-interface {v0}, Landroidx/appcompat/view/menu/h70;->c()Ljava/lang/String;

    move-result-object v0

    sput-object v0, Landroidx/appcompat/view/menu/c81$a;->c:Ljava/lang/String;

    sget-object v0, Landroidx/appcompat/view/menu/c81$a$a;->n:Landroidx/appcompat/view/menu/c81$a$a;

    invoke-static {v0}, Landroidx/appcompat/view/menu/i80;->a(Landroidx/appcompat/view/menu/hw;)Landroidx/appcompat/view/menu/f80;

    move-result-object v0

    sput-object v0, Landroidx/appcompat/view/menu/c81$a;->d:Landroidx/appcompat/view/menu/f80;

    sget-object v0, Landroidx/appcompat/view/menu/bo;->a:Landroidx/appcompat/view/menu/bo;

    sput-object v0, Landroidx/appcompat/view/menu/c81$a;->e:Landroidx/appcompat/view/menu/e81;

    return-void
.end method

.method public constructor <init>()V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public static final synthetic a()Z
    .locals 1

    sget-boolean v0, Landroidx/appcompat/view/menu/c81$a;->b:Z

    return v0
.end method

.method public static final synthetic b()Ljava/lang/String;
    .locals 1

    sget-object v0, Landroidx/appcompat/view/menu/c81$a;->c:Ljava/lang/String;

    return-object v0
.end method


# virtual methods
.method public final c()Landroidx/appcompat/view/menu/x71;
    .locals 1

    sget-object v0, Landroidx/appcompat/view/menu/c81$a;->d:Landroidx/appcompat/view/menu/f80;

    invoke-interface {v0}, Landroidx/appcompat/view/menu/f80;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Landroidx/appcompat/view/menu/x71;

    return-object v0
.end method

.method public final d(Landroid/content/Context;)Landroidx/appcompat/view/menu/c81;
    .locals 2

    const-string v0, "context"

    invoke-static {p1, v0}, Landroidx/appcompat/view/menu/x50;->e(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {p0}, Landroidx/appcompat/view/menu/c81$a;->c()Landroidx/appcompat/view/menu/x71;

    move-result-object v0

    if-nez v0, :cond_0

    sget-object v0, Landroidx/window/layout/adapter/sidecar/b;->c:Landroidx/window/layout/adapter/sidecar/b$a;

    invoke-virtual {v0, p1}, Landroidx/window/layout/adapter/sidecar/b$a;->a(Landroid/content/Context;)Landroidx/window/layout/adapter/sidecar/b;

    move-result-object v0

    :cond_0
    new-instance p1, Landroidx/appcompat/view/menu/g81;

    sget-object v1, Landroidx/appcompat/view/menu/z91;->b:Landroidx/appcompat/view/menu/z91;

    invoke-direct {p1, v1, v0}, Landroidx/appcompat/view/menu/g81;-><init>(Landroidx/appcompat/view/menu/y91;Landroidx/appcompat/view/menu/x71;)V

    sget-object v0, Landroidx/appcompat/view/menu/c81$a;->e:Landroidx/appcompat/view/menu/e81;

    invoke-interface {v0, p1}, Landroidx/appcompat/view/menu/e81;->a(Landroidx/appcompat/view/menu/c81;)Landroidx/appcompat/view/menu/c81;

    move-result-object p1

    return-object p1
.end method
