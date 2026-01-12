.class public Landroidx/appcompat/view/menu/l90;
.super Landroidx/appcompat/view/menu/k90;
.source "SourceFile"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Landroidx/appcompat/view/menu/l90$a;
    }
.end annotation


# instance fields
.field public final a:Landroidx/appcompat/view/menu/x80;

.field public final b:Landroidx/appcompat/view/menu/l90$a;


# direct methods
.method static constructor <clinit>()V
    .locals 0

    return-void
.end method

.method public constructor <init>(Landroidx/appcompat/view/menu/x80;Landroidx/appcompat/view/menu/w51;)V
    .locals 0

    invoke-direct {p0}, Landroidx/appcompat/view/menu/k90;-><init>()V

    iput-object p1, p0, Landroidx/appcompat/view/menu/l90;->a:Landroidx/appcompat/view/menu/x80;

    invoke-static {p2}, Landroidx/appcompat/view/menu/l90$a;->d(Landroidx/appcompat/view/menu/w51;)Landroidx/appcompat/view/menu/l90$a;

    move-result-object p1

    iput-object p1, p0, Landroidx/appcompat/view/menu/l90;->b:Landroidx/appcompat/view/menu/l90$a;

    return-void
.end method


# virtual methods
.method public b()V
    .locals 1

    iget-object v0, p0, Landroidx/appcompat/view/menu/l90;->b:Landroidx/appcompat/view/menu/l90$a;

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/l90$a;->e()V

    return-void
.end method

.method public toString()Ljava/lang/String;
    .locals 2

    new-instance v0, Ljava/lang/StringBuilder;

    const/16 v1, 0x80

    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(I)V

    const-string v1, "LoaderManager{"

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-static {p0}, Ljava/lang/System;->identityHashCode(Ljava/lang/Object;)I

    move-result v1

    invoke-static {v1}, Ljava/lang/Integer;->toHexString(I)Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v1, " in "

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget-object v1, p0, Landroidx/appcompat/view/menu/l90;->a:Landroidx/appcompat/view/menu/x80;

    invoke-static {v1, v0}, Landroidx/appcompat/view/menu/hj;->a(Ljava/lang/Object;Ljava/lang/StringBuilder;)V

    const-string v1, "}}"

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method
