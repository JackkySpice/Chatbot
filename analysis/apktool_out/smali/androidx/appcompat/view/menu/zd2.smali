.class public final Landroidx/appcompat/view/menu/zd2;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Landroidx/appcompat/view/menu/ay0;


# static fields
.field public static n:Landroidx/appcompat/view/menu/zd2;


# instance fields
.field public final m:Landroidx/appcompat/view/menu/ay0;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    new-instance v0, Landroidx/appcompat/view/menu/zd2;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/zd2;-><init>()V

    sput-object v0, Landroidx/appcompat/view/menu/zd2;->n:Landroidx/appcompat/view/menu/zd2;

    return-void
.end method

.method public constructor <init>()V
    .locals 1

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    new-instance v0, Landroidx/appcompat/view/menu/be2;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/be2;-><init>()V

    invoke-static {v0}, Landroidx/appcompat/view/menu/cy0;->b(Ljava/lang/Object;)Landroidx/appcompat/view/menu/ay0;

    move-result-object v0

    iput-object v0, p0, Landroidx/appcompat/view/menu/zd2;->m:Landroidx/appcompat/view/menu/ay0;

    return-void
.end method

.method public static a()Z
    .locals 1

    sget-object v0, Landroidx/appcompat/view/menu/zd2;->n:Landroidx/appcompat/view/menu/zd2;

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/zd2;->get()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Landroidx/appcompat/view/menu/ce2;

    invoke-interface {v0}, Landroidx/appcompat/view/menu/ce2;->a()Z

    move-result v0

    return v0
.end method


# virtual methods
.method public final synthetic get()Ljava/lang/Object;
    .locals 1

    iget-object v0, p0, Landroidx/appcompat/view/menu/zd2;->m:Landroidx/appcompat/view/menu/ay0;

    invoke-interface {v0}, Landroidx/appcompat/view/menu/ay0;->get()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Landroidx/appcompat/view/menu/ce2;

    return-object v0
.end method
