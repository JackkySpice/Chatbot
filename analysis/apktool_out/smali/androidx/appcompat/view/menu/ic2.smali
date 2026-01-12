.class public final Landroidx/appcompat/view/menu/ic2;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Landroidx/appcompat/view/menu/ay0;


# static fields
.field public static n:Landroidx/appcompat/view/menu/ic2;


# instance fields
.field public final m:Landroidx/appcompat/view/menu/ay0;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    new-instance v0, Landroidx/appcompat/view/menu/ic2;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/ic2;-><init>()V

    sput-object v0, Landroidx/appcompat/view/menu/ic2;->n:Landroidx/appcompat/view/menu/ic2;

    return-void
.end method

.method public constructor <init>()V
    .locals 1

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    new-instance v0, Landroidx/appcompat/view/menu/kc2;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/kc2;-><init>()V

    invoke-static {v0}, Landroidx/appcompat/view/menu/cy0;->b(Ljava/lang/Object;)Landroidx/appcompat/view/menu/ay0;

    move-result-object v0

    iput-object v0, p0, Landroidx/appcompat/view/menu/ic2;->m:Landroidx/appcompat/view/menu/ay0;

    return-void
.end method

.method public static a()D
    .locals 2

    sget-object v0, Landroidx/appcompat/view/menu/ic2;->n:Landroidx/appcompat/view/menu/ic2;

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/ic2;->get()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Landroidx/appcompat/view/menu/lc2;

    invoke-interface {v0}, Landroidx/appcompat/view/menu/lc2;->a()D

    move-result-wide v0

    return-wide v0
.end method

.method public static b()J
    .locals 2

    sget-object v0, Landroidx/appcompat/view/menu/ic2;->n:Landroidx/appcompat/view/menu/ic2;

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/ic2;->get()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Landroidx/appcompat/view/menu/lc2;

    invoke-interface {v0}, Landroidx/appcompat/view/menu/lc2;->b()J

    move-result-wide v0

    return-wide v0
.end method

.method public static c()J
    .locals 2

    sget-object v0, Landroidx/appcompat/view/menu/ic2;->n:Landroidx/appcompat/view/menu/ic2;

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/ic2;->get()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Landroidx/appcompat/view/menu/lc2;

    invoke-interface {v0}, Landroidx/appcompat/view/menu/lc2;->c()J

    move-result-wide v0

    return-wide v0
.end method

.method public static d()Ljava/lang/String;
    .locals 1

    sget-object v0, Landroidx/appcompat/view/menu/ic2;->n:Landroidx/appcompat/view/menu/ic2;

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/ic2;->get()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Landroidx/appcompat/view/menu/lc2;

    invoke-interface {v0}, Landroidx/appcompat/view/menu/lc2;->d()Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method

.method public static e()Z
    .locals 1

    sget-object v0, Landroidx/appcompat/view/menu/ic2;->n:Landroidx/appcompat/view/menu/ic2;

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/ic2;->get()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Landroidx/appcompat/view/menu/lc2;

    invoke-interface {v0}, Landroidx/appcompat/view/menu/lc2;->f()Z

    move-result v0

    return v0
.end method


# virtual methods
.method public final synthetic get()Ljava/lang/Object;
    .locals 1

    iget-object v0, p0, Landroidx/appcompat/view/menu/ic2;->m:Landroidx/appcompat/view/menu/ay0;

    invoke-interface {v0}, Landroidx/appcompat/view/menu/ay0;->get()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Landroidx/appcompat/view/menu/lc2;

    return-object v0
.end method
